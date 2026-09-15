// Acceptance tests for the Codex re-check of fix round 2 (astra/md/MANDATE-DESK-
// LIVE-AUDIT-A1-CODEX-ROUND-2-RECHECK-2026-09-15.md, 2026-09-15). Each open
// finding gets the test the re-check asked for: R2-F01 (the control check before
// the first execute signature also when a preparation is pending), R2-F02 (the
// allowance reset only for a value the run put there), R2-F03 (read-only
// tracking under a code identity mismatch), R2-F04 (the whole evidence package,
// intact and current) and R2-F05 (the signer's own identity check per
// write-capable request), plus ADV3-01 from the adversarial check of this round
// (the controls read again right before every signature). Every test states the
// corrected behaviour and fails on
// the tree the re-check audited. Everything runs on the in-memory FakeSepolia
// harness with public Hardhat test keys: no network, no real key, no chain
// write. The R2-F03 tests copy the covered source into an isolated runtime under
// test-output before they change a byte, so the repository's own files never
// change. The signer test drives the HTTP handler with an injected signer.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { ROOT } from '../src/store.mjs';
import { BrickkenLiveWorkspace } from '../src/brickken-workspace.mjs';
import { LiveBrickkenJournal } from '../src/brickken-journal.mjs';
import { LiveAdapterError, LiveStepExecutor } from '../src/brickken-live-adapter.mjs';
import { loadLiveProposal } from '../src/brickken-live-plan.mjs';
import { requiredEvidencePackageMembers } from '../src/brickken-live-completeness.mjs';
import { CODE_IDENTITY_FOLDERS } from '../src/code-identity.mjs';
import { createRoleResolver, createSignerRequestHandler } from '../src/live-signer-http.mjs';
import { FakeRpc, FakeSepolia, FakeSignerGateway, createClock } from './live-fakes.mjs';

// ---------------------------------------------------------------------------
// Harness (the same shape as test/brickken-live-a1-recheck.test.mjs)

const TRACKING_STATES = ['broadcast', 'uncertain', 'confirmed'];

function testDir(name = 'r2') {
  fs.mkdirSync(path.join(ROOT, 'test-output'), { recursive: true });
  return fs.mkdtempSync(path.join(ROOT, 'test-output', `fable-r2-${name}-`));
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
const runView = owner => owner.view().runs[0];
const controlView = (owner, id) => runView(owner).controls.find(item => item.id === id);
const signedCount = (env, step) => env.gateway.entries.filter(entry => entry.type === 'signed' && entry.step === step).length;
const minedCount = (env, predicate) => [...env.chain.transactions.values()].filter(item => predicate(item.tx)).length;
const agentTxs = env => minedCount(env, tx => tx.from === env.proposal.agent);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function exportEvidence(env, run) {
  const output = path.relative(ROOT, path.join(ROOT, 'test-output', `fable-r2-export-${randomUUID().slice(0, 8)}`));
  const result = spawnSync(process.execPath, [
    path.join(ROOT, 'tools', 'export-live-evidence.mjs'), '--data', path.relative(ROOT, env.dir), '--run', run.runId, '--output', output
  ], { cwd: ROOT, encoding: 'utf8', windowsHide: true });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, output: path.join(ROOT, output), relative: output.split(path.sep).join('/') };
}
// A signer client whose first signature of one step fails as an unavailable signer.
function failingOnceSigner(env, role, failStep) {
  const client = env.gateway.client(role);
  let remaining = 1;
  return {
    ...client,
    async sign(step, transaction) {
      if (step === failStep && remaining > 0) {
        remaining -= 1;
        throw new LiveAdapterError('SIGNER_UNAVAILABLE', { layer: 'signer', injected: true });
      }
      return client.sign(step, transaction);
    }
  };
}
// A later, independent approval by the principal to the same executor, mined
// on the fake chain outside the run's journal (the R2-F02 reproduction).
function mineForeignApproval(env, run, allowance) {
  const journal = journalOf(env);
  const prior = journal.get(opId(run, 'approve')).transaction;
  const foreign = {
    ...prior,
    nonce: env.chain.state.nonce[env.proposal.principal].toString(),
    data: prior.data.slice(0, 74) + allowance.toString(16).padStart(64, '0')
  };
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
// R2-F01: the transaction-cap control is checked before the first execute
// signature, also when a preparation is already recorded as pending

test('R2-F01: a pending execute preparation after a failed signature gets the control check again: a reorganised control block withdraws it, nothing is signed, the owner observes the control again and the retry then signs', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const before = controlView(owner, 'control-transaction-cap');
  const agent = agentOf(env, { signer: failingOnceSigner(env, 'agent', 'execute') });
  await assert.rejects(agent.agentExecute({ operationId: opId(run, 'execute') }), { code: 'SIGNER_UNAVAILABLE' });
  assert.equal(journalOf(env).get(opId(run, 'execute')).state, 'pending');
  assert.equal(signedCount(env, 'execute'), 0);

  env.chain.reorg(env.chain.latest().number - Number(before.blockNumber) + 1);
  const canonical = env.chain.blocks.find(block => String(block.number) === before.blockNumber);
  assert.notEqual(canonical.hash, before.blockHash);

  await assert.rejects(agent.agentExecute({ operationId: opId(run, 'execute') }), { code: 'CONTROL_WITHDRAWN' });
  assert.equal(signedCount(env, 'execute'), 0);
  assert.equal(agentTxs(env), 0);
  assert.equal(journalOf(env).get(opId(run, 'execute')).state, 'pending');
  const withdrawn = runView(owner);
  assert.equal(withdrawn.status, 'stopped');
  assert.equal(withdrawn.phase, 'owner-setup');
  assert.equal(withdrawn.stop.code, 'CONTROL_WITHDRAWN');
  assert.equal(controlView(owner, 'control-transaction-cap').canonical, false);
  assert.equal(controlView(owner, 'control-transaction-cap').passed, false);

  // The owner observes the control again at the same stage; the pending
  // preparation is not a write and does not block that.
  await owner.resumeRun({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'awaiting-agent', JSON.stringify(runView(owner).stop));
  const renewed = controlView(owner, 'control-transaction-cap');
  assert.equal(renewed.passed, true);
  assert.equal(renewed.canonical, true);
  assert.equal(renewed.blockHash, canonical.hash);
  assert.equal(signedCount(env, 'execute'), 0);

  const receipt = await driveAgentExecute(agent, opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  assert.equal(signedCount(env, 'execute'), 1);
  assert.equal(agentTxs(env), 1);
  assert.equal(controlView(owner, 'control-transaction-cap').blockHash, canonical.hash);
});

test('R2-F01: a pending execute preparation waits while one source has no block at the control height, and signs once both sources answer', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const control = controlView(owner, 'control-transaction-cap');
  const agent = agentOf(env, { signer: failingOnceSigner(env, 'agent', 'execute') });
  await assert.rejects(agent.agentExecute({ operationId: opId(run, 'execute') }), { code: 'SIGNER_UNAVAILABLE' });
  assert.equal(journalOf(env).get(opId(run, 'execute')).state, 'pending');

  env.rpcs.secondary.faults.hideBlock = block => String(block.number) === control.blockNumber;
  await assert.rejects(agent.agentExecute({ operationId: opId(run, 'execute') }), { code: 'CONTROL_UNRESOLVED' });
  assert.equal(signedCount(env, 'execute'), 0);
  assert.equal(agentTxs(env), 0);
  assert.equal(controlView(owner, 'control-transaction-cap').canonical, true);
  assert.equal(controlView(owner, 'control-transaction-cap').passed, true);
  assert.equal(runView(owner).phase, 'agent-execute');

  env.rpcs.secondary.faults.hideBlock = null;
  const receipt = await driveAgentExecute(agent, opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  assert.equal(signedCount(env, 'execute'), 1);
});

test('R2-F01: a control withdrawn by a finality refresh before any execute bytes exist refuses execute until the owner observes it again', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const before = controlView(owner, 'control-transaction-cap');
  env.chain.reorg(env.chain.latest().number - Number(before.blockNumber) + 1);
  const finality = await owner.refreshFinality({ runId: run.runId });
  assert.equal(finality.allFinalized, false);
  assert.equal(controlView(owner, 'control-transaction-cap').canonical, false);
  assert.equal(runView(owner).status, 'awaiting-agent');

  const agent = agentOf(env);
  await assert.rejects(agent.agentExecute({ operationId: opId(run, 'execute') }), { code: 'CONTROL_WITHDRAWN' });
  assert.equal(signedCount(env, 'execute'), 0);
  assert.equal(journalOf(env).find(opId(run, 'execute')), null);
  assert.equal(runView(owner).phase, 'owner-setup');

  await owner.resumeRun({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'awaiting-agent', JSON.stringify(runView(owner).stop));
  assert.equal(controlView(owner, 'control-transaction-cap').canonical, true);
  const receipt = await driveAgentExecute(agent, opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
});

// A read source that lets a one-block reorganisation land inside one call: the
// first nonce read for the given address replaces the chain tip, which is the
// block the most recent control observation rests on (ADV3-01).
function reorgOnFirstNonceRead(env, rpc, address) {
  const real = rpc.getTransactionCount.bind(rpc);
  let fired = 0;
  rpc.getTransactionCount = async (target, tag) => {
    if (fired === 0 && target === address) { fired += 1; env.chain.reorg(1); }
    return real(target, tag);
  };
  return () => fired;
}

test('ADV3-01: a control block reorganised after the phase check and before the signature, inside one execute call, withdraws the control and signs nothing; the owner observes it again and the retry signs', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const before = controlView(owner, 'control-transaction-cap');
  assert.equal(String(env.chain.latest().number), before.blockNumber, 'the control rests on the chain tip');
  const fired = reorgOnFirstNonceRead(env, env.rpcs.primary, env.proposal.agent);
  const agent = agentOf(env);
  await assert.rejects(agent.agentExecute({ operationId: opId(run, 'execute') }), { code: 'CONTROL_WITHDRAWN' });
  assert.equal(fired(), 1);
  assert.equal(signedCount(env, 'execute'), 0);
  assert.equal(agentTxs(env), 0);
  assert.equal(journalOf(env).get(opId(run, 'execute')).state, 'pending');
  const withdrawn = controlView(owner, 'control-transaction-cap');
  assert.equal(withdrawn.canonical, false);
  assert.equal(withdrawn.passed, false);
  assert.equal(runView(owner).phase, 'owner-setup');
  await owner.resumeRun({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'awaiting-agent', JSON.stringify(runView(owner).stop));
  assert.notEqual(controlView(owner, 'control-transaction-cap').blockHash, before.blockHash);
  const receipt = await driveAgentExecute(agent, opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  assert.equal(signedCount(env, 'execute'), 1);
});

test('ADV3-01: the pre-revocation controls reorganised between their observation and the revoke signature stop the revocation without a signature, and the resumed owner observes them again and completes', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const receipt = await driveAgentExecute(agentOf(env), opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  const fired = reorgOnFirstNonceRead(env, env.rpcs.primary, env.proposal.principal);
  await owner.startOwnerRevocation({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const stopped = runView(owner);
  assert.equal(stopped.status, 'stopped');
  assert.equal(stopped.stop.code, 'CONTROL_WITHDRAWN', JSON.stringify(stopped.stop));
  assert.equal(stopped.phase, 'owner-revocation');
  assert.equal(fired(), 1);
  assert.equal(signedCount(env, 'revoke'), 0);
  assert.equal(journalOf(env).get(opId(run, 'revoke')).state, 'pending');
  const lost = stopped.controls.filter(item => item.canonical === false).map(item => item.id);
  assert.ok(lost.length >= 1, JSON.stringify(stopped.controls));
  assert.ok(lost.every(id => ['control-cumulative-cap', 'control-before-revoke'].includes(id)), JSON.stringify(lost));
  await owner.resumeRun({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'completed', JSON.stringify(runView(owner).stop));
  assert.ok(runView(owner).controls.every(item => item.observed && item.passed && item.canonical === true));
  assert.equal(signedCount(env, 'revoke'), 1);
  assert.equal(signedCount(env, 'approveReset'), 1);
});

// ---------------------------------------------------------------------------
// R2-F02: cleanup resets only an allowance the run's own writes left on chain

test('R2-F02: a later independent approval by the principal to the same executor is not reset by cleanup, even though the run\'s own approve is verified; the value and the run\'s expected value are named', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const journal = journalOf(env);
  assert.equal(journal.get(opId(run, 'approve')).state, 'semantically_verified');
  const approvedByRun = env.chain.state.allowance;
  const foreign = approvedByRun + 777n;
  mineForeignApproval(env, run, foreign);

  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const cleaned = runView(owner);
  assert.equal(cleaned.status, 'stopped');
  assert.equal(cleaned.stop.code, 'CLEANUP_UNATTRIBUTED_ALLOWANCE', JSON.stringify(cleaned.stop));
  assert.equal(cleaned.stop.details.allowance, foreign.toString());
  assert.equal(cleaned.stop.details.expectedFromRun, approvedByRun.toString());
  assert.equal(cleaned.stop.details.attributed, null);
  assert.equal(cleaned.cleanup.allowanceResetByCleanup, false);
  assert.equal(cleaned.cleanup.allowance, foreign.toString());
  assert.deepEqual(cleaned.cleanup.problems, ['CLEANUP_UNATTRIBUTED_ALLOWANCE']);
  assert.equal(env.chain.state.allowance, foreign);
  assert.equal(signedCount(env, 'approveReset'), 0);
  // The run's own mandate is still revoked by the same cleanup.
  assert.equal(cleaned.cleanup.revokedByCleanup, true);
  assert.equal(cleaned.cleanup.mandateRevoked, true);
});

test('R2-F02: the allowance the run\'s own approve and verified execute leave behind is still reset by cleanup, and a verified approve with a postcheck failure is attributed as before', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const receipt = await driveAgentExecute(agentOf(env), opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  const approved = BigInt('0x' + journalOf(env).get(opId(run, 'approve')).transaction.data.slice(74, 138));
  const left = approved - BigInt(env.proposal.amounts.execute);
  assert.equal(env.chain.state.allowance, left);
  assert.ok(left > 0n);

  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const cleaned = runView(owner);
  assert.equal(cleaned.stop, null, JSON.stringify(cleaned.stop));
  assert.equal(cleaned.cleanup.allowanceResetByCleanup, true);
  assert.equal(cleaned.cleanup.allowance, '0');
  assert.equal(cleaned.cleanup.revokedByCleanup, true);
  assert.deepEqual(cleaned.cleanup.problems, []);
  assert.equal(env.chain.state.allowance, 0n);
  assert.equal(signedCount(env, 'approveReset'), 1);
});

// ---------------------------------------------------------------------------
// R2-F03: a process without the approved code identity still follows recorded
// transactions by reads, records receipts, and never marks a semantic result

const RUNTIME_ENTRIES = [...CODE_IDENTITY_FOLDERS, 'integration', 'vendor', 'package.json', path.join('test', 'fixtures'), path.join('test', 'live-fakes.mjs')];
function runtimeCopy(label) {
  const runtime = testDir(`f03-${label}`);
  for (const entry of RUNTIME_ENTRIES) fs.cpSync(path.join(ROOT, entry), path.join(runtime, entry), { recursive: true });
  return runtime;
}
async function loadRuntime(runtime) {
  const load = relative => import(pathToFileURL(path.join(runtime, ...relative.split('/'))).href);
  const [workspace, plan, fakes, identity, journal] = await Promise.all([
    load('src/brickken-workspace.mjs'), load('src/brickken-live-plan.mjs'), load('test/live-fakes.mjs'),
    load('src/code-identity.mjs'), load('src/brickken-journal.mjs')
  ]);
  return { ...workspace, ...plan, ...fakes, ...identity, ...journal };
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
  const owner = (overrides = {}) => new api.BrickkenLiveWorkspace(dir, { role: 'owner', signer: gateway.client('owner'), ...common, ...overrides });
  const agent = (overrides = {}) => new api.BrickkenLiveWorkspace(dir, { role: 'agent', signer: gateway.client('agent'), ...common, ...overrides });
  const driftFile = path.join(runtime, 'src', 'brickken-postcheck.mjs');
  const original = fs.readFileSync(driftFile);
  const drift = () => fs.appendFileSync(driftFile, '\n// R2-F03 acceptance: a byte changed after approval.\n');
  const restore = () => fs.writeFileSync(driftFile, original);
  const journal = () => new api.LiveBrickkenJournal({ directory: path.join(dir, 'live', 'journal') });
  // Counts every read the two sources answer, so a tracking pass is measurable.
  let reads = 0;
  for (const rpc of Object.values(rpcs)) {
    for (const name of ['getTransactionReceipt', 'getTransactionByHash', 'getTransactionCount', 'getBlock', 'blockNumber']) {
      const fn = rpc[name].bind(rpc);
      rpc[name] = async (...args) => { reads += 1; return fn(...args); };
    }
  }
  const readCount = () => reads;
  const evidence = (run, name) => fs.existsSync(path.join(dir, 'live', 'evidence', run.runId, `${name}.json`));
  return { proposal, clock, chain, rpcs, gateway, dir, sleep, common, owner, agent, drift, restore, journal, readCount, evidence };
}
async function runtimeApproved(env, owner) {
  const prepared = await owner.prepareRun();
  env.gateway.setApproval(prepared.approval);
  owner.approveRun({ runId: prepared.run.runId, approvalSha256: prepared.approval.approvalSha256, codeIdentitySha256: prepared.run.codeIdentitySha256 });
  return prepared;
}
const signedEntries = env => env.gateway.entries.filter(entry => entry.type === 'signed').length;
const sentEntries = env => env.gateway.entries.filter(entry => entry.type === 'send-attempt').length;

test('R2-F03: after expiry, an uncertain approve under a code identity mismatch is still followed by reads: the resume starts, reads happen, nothing is prepared, signed or sent, the bytes stay, and the run stops naming the mismatch and the tracked step', async () => {
  const runtime = runtimeCopy('expired');
  const api = await loadRuntime(runtime);
  const env = runtimeEnvironment(runtime, api);
  const owner = env.owner();
  const prepared = await runtimeApproved(env, owner);
  env.rpcs.primary.faults.sendErrors = Array(500).fill('RPC_TIMEOUT');
  await owner.startOwnerSetup({ runId: prepared.run.runId });
  await owner.whenIdle(prepared.run.runId);
  const stopped = owner.view().runs[0];
  assert.equal(stopped.stop.code, 'STEP_TIMEOUT', JSON.stringify(stopped.stop));
  const journal = env.journal();
  const record = journal.get(`${prepared.run.runId}_approve`);
  assert.equal(record.state, 'uncertain');
  const bytesBefore = record.signed.signedTransaction;
  const signedBefore = signedEntries(env);
  const sentBefore = sentEntries(env);

  await env.sleep(97 * 60 * 60 * 1000);
  assert.ok(env.clock.ms >= Date.parse(prepared.run.notAfter));
  env.drift();
  const readsBefore = env.readCount();
  const resumed = env.owner();
  const started = await resumed.resumeRun({ runId: prepared.run.runId });
  assert.equal(started.started, true);
  await resumed.whenIdle(prepared.run.runId);
  const after = resumed.view().runs[0];
  assert.equal(after.status, 'stopped');
  assert.equal(after.stop.code, 'CODE_IDENTITY_MISMATCH', JSON.stringify(after.stop));
  assert.equal(after.stop.details.phase, 'tracking');
  assert.equal(after.stop.details.diskCodeIdentitySha256.length, 64);
  assert.notEqual(after.stop.details.diskCodeIdentitySha256, prepared.run.codeIdentitySha256);
  assert.deepEqual(after.stop.details.tracked.map(item => [item.step, item.journalState]), [['approve', 'uncertain']]);
  assert.equal(after.stop.details.tracked[0].transactionHash, record.signed.ethereumTransactionHash);
  assert.ok(env.readCount() > readsBefore, 'the tracking pass must read the sources');
  assert.equal(signedEntries(env), signedBefore);
  assert.equal(sentEntries(env), sentBefore);
  const same = journal.get(`${prepared.run.runId}_approve`);
  assert.equal(same.state, 'uncertain');
  assert.equal(same.signed.signedTransaction, bytesBefore);
  env.restore();
});

test('R2-F03: a broadcast execute under a code identity mismatch is tracked to its receipt and no further: the agent records the receipt, marks no semantic result, signs nothing, and completes once the approved bytes are back', async () => {
  const runtime = runtimeCopy('agent');
  const api = await loadRuntime(runtime);
  const env = runtimeEnvironment(runtime, api);
  const owner = env.owner();
  const prepared = await runtimeApproved(env, owner);
  await owner.startOwnerSetup({ runId: prepared.run.runId });
  await owner.whenIdle(prepared.run.runId);
  assert.equal(owner.view().runs[0].status, 'awaiting-agent', JSON.stringify(owner.view().runs[0].stop));
  const operationId = `${prepared.run.runId}_execute`;
  // Freeze the second source's tip after the send, so the execute is mined on
  // the chain but never reaches the required depth on both sources.
  const client = env.gateway.client('agent');
  const signer = { ...client, async send(...args) { const result = await client.send(...args); env.rpcs.secondary.faults.tipBlock = env.chain.latest().number; return result; } };
  const agent = env.agent({ signer });
  const first = await agent.agentExecute({ operationId });
  assert.notEqual(first.execute.status, 'verified');
  const journal = env.journal();
  assert.ok(TRACKING_STATES.includes(journal.get(operationId).state), journal.get(operationId).state);
  assert.equal(signedEntries(env), 4);
  const sentBefore = sentEntries(env);

  env.drift();
  env.rpcs.secondary.faults.tipBlock = null;
  const readsBefore = env.readCount();
  await assert.rejects(agent.agentExecute({ operationId }), error => error.code === 'CODE_IDENTITY_MISMATCH' && error.details.phase === 'tracking' && error.details.step === 'execute');
  assert.ok(env.readCount() > readsBefore);
  const tracked = journal.get(operationId);
  assert.equal(tracked.state, 'confirmed');
  assert.equal(tracked.semanticVerification, null);
  assert.ok(env.evidence(prepared.run, `${operationId}-receipt`));
  assert.equal(env.evidence(prepared.run, `${operationId}-postcheck`), false);
  assert.equal(signedEntries(env), 4);
  assert.equal(sentEntries(env), sentBefore);
  assert.equal(owner.view().runs[0].steps.find(step => step.step === 'execute').status, 'confirmed');

  env.restore();
  let receipt;
  for (let attempt = 0; attempt < 15; attempt++) {
    receipt = await agent.agentExecute({ operationId });
    if (receipt.execute.status === 'verified') break;
  }
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  assert.ok(env.evidence(prepared.run, `${operationId}-postcheck`));
  assert.equal(signedEntries(env), 4);
});

test('R2-F03: an owner revoke that stopped as broadcast is tracked to its receipt under a code identity mismatch before expiry, the run stops naming the confirmed step, and the restored code verifies it and completes the run', async () => {
  const runtime = runtimeCopy('owner');
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
  const client = env.gateway.client('owner');
  const signer = { ...client, async send(...args) { const result = await client.send(...args); if (args[0] === 'revoke') env.rpcs.secondary.faults.tipBlock = env.chain.latest().number; return result; } };
  const revoking = env.owner({ signer });
  await revoking.startOwnerRevocation({ runId: prepared.run.runId });
  await revoking.whenIdle(prepared.run.runId);
  const stopped = revoking.view().runs[0];
  assert.equal(stopped.stop.code, 'STEP_TIMEOUT', JSON.stringify(stopped.stop));
  const journal = env.journal();
  const revokeId = `${prepared.run.runId}_revoke`;
  assert.ok(TRACKING_STATES.includes(journal.get(revokeId).state));
  assert.ok(env.clock.ms < Date.parse(prepared.run.notAfter));
  const signedBefore = signedEntries(env);

  env.drift();
  env.rpcs.secondary.faults.tipBlock = null;
  const drifted = env.owner();
  const started = await drifted.resumeRun({ runId: prepared.run.runId });
  assert.equal(started.started, true);
  await drifted.whenIdle(prepared.run.runId);
  const after = drifted.view().runs[0];
  assert.equal(after.stop.code, 'CODE_IDENTITY_MISMATCH', JSON.stringify(after.stop));
  assert.equal(after.stop.details.phase, 'tracking');
  assert.deepEqual(after.stop.details.tracked.map(item => [item.step, item.code, item.journalState]), [['revoke', 'CODE_IDENTITY_MISMATCH', 'confirmed']]);
  assert.equal(journal.get(revokeId).state, 'confirmed');
  assert.ok(env.evidence(prepared.run, `${revokeId}-receipt`));
  assert.equal(env.evidence(prepared.run, `${revokeId}-postcheck`), false);
  assert.equal(signedEntries(env), signedBefore);
  assert.equal(after.phase, 'owner-revocation');

  env.restore();
  const restored = env.owner();
  await restored.resumeRun({ runId: prepared.run.runId });
  await restored.whenIdle(prepared.run.runId);
  assert.equal(restored.view().runs[0].status, 'completed', JSON.stringify(restored.view().runs[0].stop));
  assert.equal(journal.get(revokeId).state, 'semantically_verified');
  assert.ok(env.evidence(prepared.run, `${revokeId}-postcheck`));
  assert.equal(signedEntries(env), signedBefore + 1);
});

test('R2-F03: a code identity mismatch with nothing to track still refuses the resume, and the executor refuses to drop semantic verification outside tracking-only mode', async () => {
  const runtime = runtimeCopy('nothing');
  const api = await loadRuntime(runtime);
  const env = runtimeEnvironment(runtime, api);
  const owner = env.owner();
  const prepared = await runtimeApproved(env, owner);
  env.drift();
  await assert.rejects(owner.startOwnerSetup({ runId: prepared.run.runId }), { code: 'CODE_IDENTITY_MISMATCH' });
  await assert.rejects(owner.resumeRun({ runId: prepared.run.runId }), { code: 'RUN_STATE' });
  env.restore();
  const proposal = loadLiveProposal();
  const plain = environment();
  assert.throws(() => new LiveStepExecutor({
    proposal, rpcs: plain.rpcs, signer: plain.gateway.client('owner'), journal: journalOf(plain), approvalSha256: 'a'.repeat(64), semanticVerification: false
  }), { code: 'CONFIGURATION' });
});

// ---------------------------------------------------------------------------
// R2-F04: the evidence package is whole, intact and current, or it binds nothing

test('R2-F04: a damaged or missing package member, and a package exported before a write was re-mined into another block, refuse the recording binding with the reason named; a fresh export binds again', async () => {
  const env = environment();
  const { owner, run } = await completeRun(env);
  await env.sleep(40 * 12 * 1000);
  assert.equal((await owner.refreshFinality({ runId: run.runId })).allFinalized, true);
  const exported = exportEvidence(env, run);
  assert.equal(exported.status, 0, exported.stderr);
  const sumsBefore = fs.readFileSync(path.join(exported.output, 'SHA256SUMS.json'));
  const sums = JSON.parse(sumsBefore.toString('utf8'));
  const stored = { steps: Object.fromEntries(runView(owner).steps.map(step => [step.step, { planned: step.planned }])) };
  for (const member of requiredEvidencePackageMembers(stored)) assert.ok(Object.hasOwn(sums, member), member);
  const initial = owner.recordingBinding(run.runId, { packageDirectory: exported.relative });
  assert.equal(initial.evidencePackage.sha256sumsSha256, sha256(sumsBefore));

  // A: one exported receipt is damaged; the checksum table is untouched.
  const receiptFile = path.join(exported.output, 'steps', 'approveReset-receipt.json');
  const receiptBefore = fs.readFileSync(receiptFile);
  fs.writeFileSync(receiptFile, Buffer.from('{"corrupted":true}\n'));
  assert.throws(() => owner.recordingBinding(run.runId, { packageDirectory: exported.relative }),
    error => error.code === 'RECORDING_PACKAGE_MISMATCH' && error.details.reason === 'MEMBER_HASH' && error.details.member === 'steps/approveReset-receipt.json');
  fs.writeFileSync(receiptFile, receiptBefore);
  // A member listed in the table is missing.
  const controlFile = path.join(exported.output, 'controls', 'control-transaction-cap.json');
  const controlBefore = fs.readFileSync(controlFile);
  fs.unlinkSync(controlFile);
  assert.throws(() => owner.recordingBinding(run.runId, { packageDirectory: exported.relative }),
    error => error.code === 'RECORDING_PACKAGE_MISMATCH' && error.details.reason === 'MEMBER_MISSING' && error.details.member === 'controls/control-transaction-cap.json');
  fs.writeFileSync(controlFile, controlBefore);
  // A checksum table that omits a required member is not a complete package.
  const sumsFile = path.join(exported.output, 'SHA256SUMS.json');
  const pruned = { ...sums };
  delete pruned['steps/execute-postcheck.json'];
  fs.writeFileSync(sumsFile, JSON.stringify(pruned, null, 2) + '\n');
  assert.throws(() => owner.recordingBinding(run.runId, { packageDirectory: exported.relative }),
    error => error.code === 'RECORDING_PACKAGE_MISMATCH' && error.details.reason === 'MEMBER_MISSING' && error.details.member === 'steps/execute-postcheck.json');
  fs.writeFileSync(sumsFile, sumsBefore);
  assert.equal(owner.recordingBinding(run.runId, { packageDirectory: exported.relative }).evidencePackage.sha256sumsSha256, sha256(sumsBefore));

  // B: an exceptional deep reorganisation re-mines the approve reset into
  // another block after the export (a fixture, not a claim about Sepolia).
  const oldReset = runView(owner).steps.find(step => step.step === 'approveReset');
  env.chain.reorg(env.chain.latest().number - Number(oldReset.blockNumber) + 1);
  assert.equal((await owner.refreshFinality({ runId: run.runId })).allFinalized, false);
  await owner.resumeRun({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'completed', JSON.stringify(runView(owner).stop));
  await env.sleep(40 * 12 * 1000);
  assert.equal((await owner.refreshFinality({ runId: run.runId })).allFinalized, true);
  const newReset = runView(owner).steps.find(step => step.step === 'approveReset');
  assert.equal(newReset.transactionHash, oldReset.transactionHash);
  assert.notEqual(newReset.blockHash, oldReset.blockHash);
  assert.equal(sha256(fs.readFileSync(sumsFile)), sha256(sumsBefore));
  assert.throws(() => owner.recordingBinding(run.runId, { packageDirectory: exported.relative }),
    error => error.code === 'RECORDING_PACKAGE_MISMATCH' && error.details.reason === 'STALE_TRANSACTION' && error.details.step === 'approveReset');

  const again = exportEvidence(env, run);
  assert.equal(again.status, 0, again.stderr);
  const sumsAfter = fs.readFileSync(path.join(again.output, 'SHA256SUMS.json'));
  assert.notEqual(sha256(sumsAfter), sha256(sumsBefore));
  const fresh = owner.recordingBinding(run.runId, { packageDirectory: again.relative });
  assert.equal(fresh.evidencePackage.sha256sumsSha256, sha256(sumsAfter));
  assert.equal(fresh.transactions.find(item => item.step === 'approveReset').blockHash, newReset.blockHash);
  // A later finality reading with the same result keeps a package current.
  await env.sleep(12 * 1000);
  assert.equal((await owner.refreshFinality({ runId: run.runId })).allFinalized, true);
  assert.equal(owner.recordingBinding(run.runId, { packageDirectory: again.relative }).evidencePackage.sha256sumsSha256, sha256(sumsAfter));
});

// ---------------------------------------------------------------------------
// R2-F05: the signer checks its own code identity per write-capable request

function fakeSigner() {
  const calls = { prepare: 0, sign: 0, send: 0, transactionStatus: 0, status: 0 };
  let gate = null;
  return {
    calls,
    hold() { let release; gate = new Promise(resolve => { release = resolve; }); return release; },
    status() { calls.status += 1; return { approvalSha256: 'a'.repeat(64), codeIdentitySha256: 'b'.repeat(64), active: true, notAfter: '2026-09-16T00:00:00.000Z', signed: [] }; },
    async prepare(request) { calls.prepare += 1; if (gate) await gate; return { prepared: request.step }; },
    sign(request) { calls.sign += 1; return { signed: request.step }; },
    async send(request) { calls.send += 1; return { sent: request.step }; },
    async transactionStatus(request) { calls.transactionStatus += 1; return { status: request.step }; }
  };
}
async function withSignerServer(identity, work) {
  const signer = fakeSigner();
  const tokens = { owner: 'c'.repeat(64), agent: 'd'.repeat(64) };
  const server = http.createServer(createSignerRequestHandler({
    signer, roleFor: createRoleResolver(tokens), port: () => server.address().port, identity
  }));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const call = (route, body, { role = 'owner', method = 'POST', headers = {} } = {}) => new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    const request = http.request({
      host: '127.0.0.1', port, path: route, method,
      headers: { host: `127.0.0.1:${port}`, authorization: `Bearer ${tokens[role]}`, ...(payload === null ? {} : { 'content-type': 'application/json' }), ...headers }
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    request.on('error', reject);
    if (payload !== null) request.write(payload);
    request.end();
  });
  try { await work({ signer, call, tokens }); }
  finally { await new Promise(resolve => server.close(resolve)); }
}

test('R2-F05: the signer refuses prepare, sign and send with CODE_IDENTITY_MISMATCH when the files on disk or the process differ from the approved identity, keeps status and transaction-status readable, and serves again once the bytes are back', async () => {
  const approved = 'b'.repeat(64);
  let disk = approved;
  await withSignerServer({ approved, process: approved, disk: () => disk }, async ({ signer, call }) => {
    assert.equal((await call('/v1/prepare', { step: 'approve', body: {} })).status, 200);
    assert.equal(signer.calls.prepare, 1);
    disk = 'e'.repeat(64);
    for (const [route, body] of [['/v1/prepare', { step: 'approve', body: {} }], ['/v1/sign', { step: 'approve', transaction: {} }], ['/v1/send', { step: 'approve', txId: null, signedTransaction: '0x' }]]) {
      const refused = await call(route, body);
      assert.equal(refused.status, 409, route);
      assert.equal(refused.body.error, 'CODE_IDENTITY_MISMATCH', route);
      assert.equal(refused.body.details.codeIdentitySha256, approved);
      assert.equal(refused.body.details.diskCodeIdentitySha256, disk);
      assert.equal(refused.body.details.route, route.slice(4));
    }
    assert.deepEqual([signer.calls.prepare, signer.calls.sign, signer.calls.send], [1, 0, 0]);
    const status = await call('/v1/status', undefined, { method: 'GET' });
    assert.equal(status.status, 200);
    assert.equal(status.body.role, 'owner');
    const tracking = await call('/v1/transaction-status', { step: 'approve' });
    assert.equal(tracking.status, 200);
    assert.equal(signer.calls.transactionStatus, 1);
    disk = approved;
    assert.equal((await call('/v1/sign', { step: 'approve', transaction: {} })).status, 200);
    assert.equal(signer.calls.sign, 1);
    // The origin and token rules of the wrapper are unchanged by the move.
    assert.equal((await call('/v1/prepare', { step: 'approve', body: {} }, { headers: { origin: 'http://127.0.0.1' } })).status, 403);
    assert.equal((await call('/v1/prepare', { step: 'approve', body: {} }, { headers: { authorization: 'Bearer ' + 'f'.repeat(64) } })).status, 401);
    assert.equal((await call('/v1/unknown', { step: 'approve' })).status, 404);
  });
  // A process identity that differs from the approved one refuses every write
  // even while the disk matches: the started process is not the approved code.
  await withSignerServer({ approved, process: 'e'.repeat(64), disk: () => approved }, async ({ signer, call }) => {
    const refused = await call('/v1/send', { step: 'approve', txId: null, signedTransaction: '0x' });
    assert.equal(refused.status, 409);
    assert.equal(refused.body.details.processCodeIdentitySha256, 'e'.repeat(64));
    assert.equal(signer.calls.send, 0);
  });
  // An unreadable identity refuses too.
  await withSignerServer({ approved, process: approved, disk: () => { const error = new Error('gone'); error.code = 'CODE_IDENTITY_MISSING'; throw error; } }, async ({ signer, call }) => {
    const refused = await call('/v1/prepare', { step: 'approve', body: {} });
    assert.equal(refused.body.error, 'CODE_IDENTITY_MISMATCH');
    assert.equal(refused.body.details.reason, 'CODE_IDENTITY_MISSING');
    assert.equal(signer.calls.prepare, 0);
  });
});

test('R2-F05: the identity is read inside the serialized queue after the wait, so a request that queued behind a slow one is refused by a change that happened while it waited', async () => {
  const approved = 'b'.repeat(64);
  let disk = approved;
  await withSignerServer({ approved, process: approved, disk: () => disk }, async ({ signer, call }) => {
    const release = signer.hold();
    const first = call('/v1/prepare', { step: 'approve', body: {} });
    // Wait until the first request has reached the signer, then queue the second.
    while (signer.calls.prepare < 1) await new Promise(resolve => setTimeout(resolve, 5));
    const second = call('/v1/sign', { step: 'approve', transaction: {} });
    await new Promise(resolve => setTimeout(resolve, 20));
    disk = 'e'.repeat(64);
    release();
    assert.equal((await first).status, 200);
    const refused = await second;
    assert.equal(refused.status, 409);
    assert.equal(refused.body.error, 'CODE_IDENTITY_MISMATCH');
    assert.equal(signer.calls.sign, 0);
  });
});
