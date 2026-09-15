// Scenario suite for the live Sepolia adapter/workspace/journal stack, built
// on the in-memory FakeSepolia harness from test/live-fakes.mjs. Every test
// proves both a stopping code (or a completion) AND the absence of any
// unintended chain effect, by reading chain.state, chain.transactions and
// gateway.entries directly rather than trusting a status string alone.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT } from '../src/store.mjs';
import { BrickkenLiveWorkspace, BrickkenWorkspaceError } from '../src/brickken-workspace.mjs';
import { McpLiveSession } from '../src/mcp-integration.mjs';
import { loadLiveProposal, buildRunApproval } from '../src/brickken-live-plan.mjs';
import { readLivePreflight } from '../src/brickken-live-adapter.mjs';
import { signLiveTransaction } from '../src/brickken-live-signer.mjs';
import { EVENT_TOPICS } from '../src/brickken-postcheck.mjs';
import { FakeRpc, FakeSepolia, FakeSignerGateway, createClock, GWEI } from './live-fakes.mjs';

// ---------------------------------------------------------------------------
// Environment and workspace helpers

function testDir() {
  fs.mkdirSync(path.join(ROOT, 'test-output'), { recursive: true });
  return fs.mkdtempSync(path.join(ROOT, 'test-output', 'live-workspace-'));
}

// One fresh, isolated fake Sepolia environment per test: a proposal-bound
// chain, two RPC endpoints reading that same chain, a signer gateway that
// applies the real signer policy, and this test's own data directory.
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

// Prepares and owner-approves a run without running owner setup yet, so a
// test can inject a fault right before the specific step it targets.
async function ownerApproved(env) {
  const owner = ownerOf(env);
  const { run, approval } = await owner.prepareRun();
  env.gateway.setApproval(approval);
  owner.approveRun({ runId: run.runId, approvalSha256: approval.approvalSha256 });
  return { owner, run, approval };
}

// Drives one live run from a fresh owner instance up to 'awaiting-agent':
// prepare, owner approval, and owner setup (setAction + approve + grant +
// the transaction-cap control). Matches the working reference smoke script.
async function setupToAwaitingAgent(env) {
  const { owner, run, approval } = await ownerApproved(env);
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const status = owner.view().runs[0].status;
  if (status !== 'awaiting-agent') {
    throw new Error(`owner setup did not reach awaiting-agent (got ${status}): ${JSON.stringify(owner.view().runs[0].stop)}`);
  }
  return { owner, run, approval };
}

async function ready(session) {
  await session.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', clientInfo: { name: 'test', version: '1' }, capabilities: {} } });
  await session.handle({ jsonrpc: '2.0', method: 'notifications/initialized' });
}
async function call(session, name, args = {}) {
  const response = await session.handle({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name, arguments: args } });
  return response.result;
}

// Repeats execute_approved through the MCP session until verified, an error
// comes back, or attempts run out. Each attempt has its own internal
// deadline, so a normal run can need more than one call to finish.
async function driveExecuteViaSession(session, operationId, attempts = 15) {
  let last;
  for (let i = 0; i < attempts; i++) {
    last = await call(session, 'execute_approved', { operationId });
    if (last.isError || last.structuredContent.execute.status === 'verified') return last;
  }
  return last;
}
// Same idea, calling the workspace directly instead of through MCP. Throws
// if agentExecute itself rejects (a genuine stop), which callers expecting a
// stop should catch, and callers expecting success should let propagate.
async function driveAgentExecute(agent, operationId, attempts = 15) {
  let last;
  for (let i = 0; i < attempts; i++) {
    last = await agent.agentExecute({ operationId });
    if (last.execute.status === 'verified') return last;
  }
  return last;
}

function isoAt(ms) { return new Date(ms).toISOString(); }
function tokenBalances(env) {
  return {
    principal: BigInt(env.chain.state.token[env.proposal.principal] ?? 0n),
    recipient: BigInt(env.chain.state.token[env.proposal.recipient.address] ?? 0n)
  };
}
function agentTransactionCount(env) {
  return [...env.chain.transactions.values()].filter(entry => entry.tx.from === env.proposal.agent).length;
}
function signedCount(env, step) {
  return env.gateway.entries.filter(entry => entry.type === 'signed' && entry.step === step).length;
}
// A run view's `steps` is an array of per-step objects (see #runView in
// brickken-workspace.mjs), not an object keyed by step name.
function stepOf(run, step) {
  const found = run.steps.find(item => item.step === step);
  if (!found) throw new Error(`run view has no step named ${step}`);
  return found;
}
function executeOperationId(run) { return stepOf(run, 'execute').operationId; }

// ---------------------------------------------------------------------------
// 1. Happy path through McpLiveSession, with a replay

test('happy path through McpLiveSession: tool list, execute, replay, revoke and finality', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const balancesBefore = tokenBalances(env);
  const amount = BigInt(env.proposal.amounts.execute);

  const agent = agentOf(env);
  const session = new McpLiveSession(agent);
  await ready(session);

  const toolsList = await session.handle({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
  assert.deepEqual(toolsList.result.tools.map(tool => tool.name), ['get_context', 'preflight', 'execute_approved', 'get_receipt']);

  const context = await call(session, 'get_context', {});
  const operationId = context.structuredContent.activeRun.executeOperationId;
  assert.equal(operationId, executeOperationId(run));
  assert.equal(context.structuredContent.activeRun.executeAvailable, true);

  const preflight = await call(session, 'preflight', { operationId });
  assert.equal(preflight.isError, false);

  const finalExecute = await driveExecuteViaSession(session, operationId);
  assert.equal(finalExecute.isError, false, JSON.stringify(finalExecute));
  assert.equal(finalExecute.structuredContent.execute.status, 'verified');
  assert.equal(finalExecute.structuredContent.execute.semanticallyVerified, true);

  assert.equal(env.chain.state.nonce[env.proposal.agent], 1);
  assert.equal(agentTransactionCount(env), 1);
  const balancesAfterExecute = tokenBalances(env);
  assert.equal(balancesAfterExecute.principal, balancesBefore.principal - amount);
  assert.equal(balancesAfterExecute.recipient, balancesBefore.recipient + amount);

  const replay = await call(session, 'execute_approved', { operationId });
  assert.equal(replay.isError, false);
  const lastReplay = replay.structuredContent.replays.at(-1);
  assert.equal(lastReplay.passed, true);
  assert.equal(lastReplay.newAgentTransaction, false);
  // A replay never sends anything: nonce and balances stay exactly as after the first execute.
  assert.equal(env.chain.state.nonce[env.proposal.agent], 1);
  assert.deepEqual(tokenBalances(env), balancesAfterExecute);

  assert.equal(owner.view().runs[0].status, 'awaiting-owner-revocation');
  await owner.startOwnerRevocation({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const view = owner.view().runs[0];
  assert.equal(view.status, 'completed');
  assert.ok(view.steps.every(step => step.status === 'verified'), JSON.stringify(view.steps.map(s => [s.step, s.status])));
  assert.equal(env.chain.state.allowance, 0n);
  assert.equal(env.chain.state.mandate.revoked, true);

  await env.sleep(40 * 12 * 1000);
  const finality = await owner.refreshFinality({ runId: run.runId });
  assert.equal(finality.allFinalized, true);

  // Exactly one agent transaction across the whole run: the execute itself.
  assert.equal(agentTransactionCount(env), 1);
});

// ---------------------------------------------------------------------------
// 2. Wrong recipient from Brickken prepare

test('wrong recipient from Brickken prepare stops execute with no signature and no transfer', async () => {
  const env = environment();
  const { run } = await setupToAwaitingAgent(env);
  const agent = agentOf(env);
  const balancesBefore = tokenBalances(env);
  const txCountBefore = env.chain.transactions.size;

  env.gateway.faults.prepare = ['WRONG_RECIPIENT'];
  let caught = null;
  try { await agent.agentExecute({ operationId: executeOperationId(run) }); }
  catch (error) { caught = error; }
  assert.ok(caught instanceof BrickkenWorkspaceError, 'execute must stop rather than send a mismatched recipient');

  const stepView = agent.view().runs[0].steps.find(step => step.step === 'execute');
  assert.equal(stepView.journalState, null);
  assert.equal(stepView.transactionHash, null);
  assert.deepEqual(tokenBalances(env), balancesBefore);
  assert.equal(env.chain.transactions.size, txCountBefore);
  assert.equal(signedCount(env, 'execute'), 0);
});

// ---------------------------------------------------------------------------
// 3. Fee above the approved ceiling from Brickken (HIGH_FEE) at grant

test('fee above the approved ceiling from Brickken stops owner setup before a grant signature', async () => {
  const env = environment();
  const { owner, run } = await ownerApproved(env);
  // setAction is prepared through the same Brickken route first; leave its
  // slot fault-free so only the grant preparation receives HIGH_FEE.
  env.gateway.faults.prepare = [undefined, 'HIGH_FEE'];

  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const view = owner.view().runs[0];
  assert.equal(view.status, 'stopped');
  assert.equal(view.stop.code, 'FEE_CEILING', JSON.stringify(view.stop));

  const grantStep = view.steps.find(step => step.step === 'grant');
  assert.equal(grantStep.journalState, null);
  assert.equal(env.chain.state.mandate, null);
  assert.equal(signedCount(env, 'grant'), 0);
});

// ---------------------------------------------------------------------------
// 4. HTTP 402 at setAction prepare

test('HTTP 402 at setAction prepare stops with PAYMENT_REQUIRED and signs nothing', async () => {
  const env = environment();
  const { owner, run } = await ownerApproved(env);
  env.gateway.faults.prepare = ['PAYMENT_REQUIRED'];

  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const view = owner.view().runs[0];
  assert.equal(view.status, 'stopped');
  assert.equal(view.stop.code, 'PAYMENT_REQUIRED');
  assert.equal(view.stop.details.layer, 'brickken-api');

  // The reviewed proposal itself carries no payment fallback, and nothing was signed.
  assert.equal(env.proposal.routes.brickkenApi.paymentFallback, false);
  assert.equal(env.gateway.entries.filter(entry => entry.type === 'signed').length, 0);
  const setActionStep = view.steps.find(step => step.step === 'setAction');
  assert.equal(setActionStep.journalState, null);
});

// ---------------------------------------------------------------------------
// 5. Missing signer whitelist

test('missing signer whitelist stops with HTTP_REJECTED and the Brickken error code', async () => {
  const env = environment();
  const { owner, run } = await ownerApproved(env);
  env.gateway.faults.prepare = ['SIGNER_NOT_WHITELISTED'];

  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const view = owner.view().runs[0];
  assert.equal(view.status, 'stopped');
  assert.equal(view.stop.code, 'HTTP_REJECTED');
  assert.equal(view.stop.details.apiErrorCode, 'SIGNER_NOT_WHITELISTED');
  assert.equal(env.gateway.entries.filter(entry => entry.type === 'signed').length, 0);
});

// ---------------------------------------------------------------------------
// 6. Base fee above the approved ceiling

test('base fee above the approved ceiling stops before any signature', async () => {
  const env = environment({ baseFeePerGas: 26n * GWEI });

  const preflight = await readLivePreflight({ proposal: env.proposal, rpcs: env.rpcs, now: () => env.clock.ms, sleep: env.sleep });
  assert.ok(preflight.blockers.some(blocker => blocker.code === 'FEE_CEILING_REACHED'), JSON.stringify(preflight.blockers));

  const { owner, run } = await ownerApproved(env);
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const view = owner.view().runs[0];
  assert.equal(view.status, 'stopped');
  assert.equal(view.stop.code, 'PREFLIGHT_BLOCKED');
  assert.ok(view.stop.details.blockers.some(blocker => blocker.code === 'FEE_CEILING_REACHED'), JSON.stringify(view.stop.details));
  assert.ok(view.steps.every(step => step.journalState === null));
  assert.equal(env.gateway.entries.filter(entry => entry.type === 'signed').length, 0);
});

// ---------------------------------------------------------------------------
// 7. Signer approval mismatch and expiry

test('a mismatched or expired approval stops startOwnerSetup and changes nothing', async () => {
  const env = environment();
  const { owner, run, approval } = await ownerApproved(env);

  const different = buildRunApproval(env.proposal, {
    createdAt: isoAt(env.clock.ms - 1_000),
    notAfter: isoAt(env.clock.ms - 1_000 + 72 * 3600 * 1000),
    preflight: null
  });
  assert.notEqual(different.approvalSha256, approval.approvalSha256);
  env.gateway.setApproval(different);

  await assert.rejects(
    owner.startOwnerSetup({ runId: run.runId }),
    error => error instanceof BrickkenWorkspaceError && error.code === 'SIGNER_APPROVAL_MISMATCH'
  );
  assert.equal(owner.view().runs[0].status, 'owner-approved');
  assert.equal(env.gateway.entries.length, 0);

  // Restore the matching approval, then let the clock pass the run's own expiry.
  env.gateway.setApproval(approval);
  env.clock.ms = Date.parse(run.notAfter) + 1_000;
  await assert.rejects(
    owner.startOwnerSetup({ runId: run.runId }),
    error => error instanceof BrickkenWorkspaceError && error.code === 'APPROVAL_EXPIRED'
  );
  assert.equal(owner.view().runs[0].status, 'owner-approved');
  assert.equal(env.gateway.entries.length, 0);
});

// ---------------------------------------------------------------------------
// 8. Timeout after send, transaction actually accepted

test('a send timeout with the transaction actually accepted ends verified with exactly one transfer', async () => {
  const env = environment();
  const { run } = await setupToAwaitingAgent(env);
  const agent = agentOf(env);
  const balancesBefore = tokenBalances(env);
  const amount = BigInt(env.proposal.amounts.execute);

  env.gateway.faults.send = ['TIMEOUT_ACCEPTED'];
  const receipt = await driveAgentExecute(agent, executeOperationId(run));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt));

  const balancesAfter = tokenBalances(env);
  assert.equal(balancesAfter.principal, balancesBefore.principal - amount);
  assert.equal(balancesAfter.recipient, balancesBefore.recipient + amount);
  assert.equal(agentTransactionCount(env), 1);
  assert.equal(env.chain.state.nonce[env.proposal.agent], 1);
  assert.equal(signedCount(env, 'execute'), 1);
});

// ---------------------------------------------------------------------------
// 9. Timeout after send, transaction never accepted

test('a send timeout with the transaction never accepted resends only the identical signed bytes', async () => {
  const env = environment();
  const { run } = await setupToAwaitingAgent(env);
  const agent = agentOf(env);
  const balancesBefore = tokenBalances(env);
  const amount = BigInt(env.proposal.amounts.execute);

  env.gateway.faults.send = ['TIMEOUT_DROPPED'];
  const receipt = await driveAgentExecute(agent, executeOperationId(run), 25);
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt));

  const balancesAfter = tokenBalances(env);
  assert.equal(balancesAfter.principal, balancesBefore.principal - amount);
  assert.equal(balancesAfter.recipient, balancesBefore.recipient + amount);
  assert.equal(agentTransactionCount(env), 1);
  const signed = env.gateway.entries.filter(entry => entry.type === 'signed' && entry.step === 'execute');
  assert.equal(signed.length, 1);
  assert.equal(signed[0].transactionHash, receipt.execute.transactionHash);
});

// ---------------------------------------------------------------------------
// 10. Restart with a fresh workspace and signer instance

test('restart with a fresh workspace and signer instance resumes without a second signature', async () => {
  const env = environment();
  const { run, approval } = await setupToAwaitingAgent(env);

  // A brand-new signer process shares only its persisted, append-only entries
  // log and the run approval file - exactly what a real restart restores.
  const gateway2 = new FakeSignerGateway({ chain: env.chain, proposal: env.proposal, clock: env.clock });
  gateway2.entries = env.gateway.entries;
  // The fake gateway's txId counter is per-instance, unlike a real Brickken
  // account; carry it over too so a restarted signer process cannot mint a
  // txId that collides with one already recorded in the shared journal.
  gateway2.counter = env.gateway.counter;
  gateway2.setApproval(approval);
  const common2 = { ...env.common, verifySignedTransaction: gateway2.verify };
  const owner2 = new BrickkenLiveWorkspace(env.dir, { role: 'owner', signer: gateway2.client('owner'), ...common2 });
  const agent2 = new BrickkenLiveWorkspace(env.dir, { role: 'agent', signer: gateway2.client('agent'), ...common2 });

  const balancesBefore = tokenBalances(env);
  const amount = BigInt(env.proposal.amounts.execute);
  const receipt = await driveAgentExecute(agent2, executeOperationId(run));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt));

  await owner2.startOwnerRevocation({ runId: run.runId });
  await owner2.whenIdle(run.runId);
  const view = owner2.view().runs[0];
  assert.equal(view.status, 'completed');

  const balancesAfter = tokenBalances(env);
  assert.equal(balancesAfter.principal, balancesBefore.principal - amount);
  assert.equal(balancesAfter.recipient, balancesBefore.recipient + amount);
  assert.equal(agentTransactionCount(env), 1);
  assert.equal(signedCount(env, 'execute'), 1);
  assert.equal(signedCount(env, 'revoke'), 1);
});

// ---------------------------------------------------------------------------
// 11. Two concurrent execute_approved calls

test('two concurrent execute_approved calls never produce two transfers', async () => {
  const env = environment();
  const { run } = await setupToAwaitingAgent(env);
  const agent1 = agentOf(env);
  const agent2 = agentOf(env);
  const balancesBefore = tokenBalances(env);
  const amount = BigInt(env.proposal.amounts.execute);

  const results = await Promise.allSettled([
    driveAgentExecute(agent1, executeOperationId(run)),
    driveAgentExecute(agent2, executeOperationId(run))
  ]);
  const fulfilled = results.filter(result => result.status === 'fulfilled');
  const rejected = results.filter(result => result.status === 'rejected');

  if (rejected.length > 0) {
    assert.equal(rejected.length, 1, JSON.stringify(results));
    assert.equal(rejected[0].reason.code, 'LIVE_RUN_BUSY');
    assert.equal(fulfilled.length, 1);
    assert.equal(fulfilled[0].value.execute.status, 'verified');
  } else {
    assert.equal(fulfilled.length, 2);
    assert.equal(fulfilled[0].value.execute.status, 'verified');
    assert.equal(fulfilled[1].value.execute.status, 'verified');
    assert.equal(fulfilled[0].value.execute.transactionHash, fulfilled[1].value.execute.transactionHash);
  }

  const balancesAfter = tokenBalances(env);
  assert.equal(balancesAfter.principal, balancesBefore.principal - amount);
  assert.equal(balancesAfter.recipient, balancesBefore.recipient + amount);
  assert.equal(agentTransactionCount(env), 1);
  assert.equal(signedCount(env, 'execute'), 1);
});

// ---------------------------------------------------------------------------
// 12. Reorganisation after execute is verified

test('a reorganisation after execute is verified still lets the run complete with exactly one transfer', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const agent = agentOf(env);
  const balancesBefore = tokenBalances(env);
  const amount = BigInt(env.proposal.amounts.execute);

  const receipt = await driveAgentExecute(agent, executeOperationId(run));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt));
  const originalBlockHash = receipt.execute.blockHash;
  assert.ok(originalBlockHash);

  // Reorg immediately: no extra block was mined since execute's confirmation,
  // so depth 2 replaces exactly the block execute is in and the one on top of it.
  env.chain.reorg(2);

  await owner.startOwnerRevocation({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const view = owner.view().runs[0];
  assert.equal(view.status, 'completed', JSON.stringify(view.stop));

  const executeStep = view.steps.find(step => step.step === 'execute');
  assert.equal(executeStep.semanticallyVerified, true, `execute ended at journalState=${executeStep.journalState} instead of semantically_verified`);
  assert.notEqual(executeStep.blockHash, originalBlockHash);

  const balancesAfter = tokenBalances(env);
  assert.equal(balancesAfter.principal, balancesBefore.principal - amount);
  assert.equal(balancesAfter.recipient, balancesBefore.recipient + amount);
  assert.equal(agentTransactionCount(env), 1);
  assert.equal(signedCount(env, 'execute'), 1);
});

// ---------------------------------------------------------------------------
// 13. Forged receipt

test('a forged receipt event fails the semantic check and never reports execute verified', async () => {
  const env = environment();
  const { run } = await setupToAwaitingAgent(env);
  const agent = agentOf(env);
  const balancesBefore = tokenBalances(env);
  const amount = BigInt(env.proposal.amounts.execute);

  env.rpcs.primary.faults.forgeReceipt = receipt => ({
    ...receipt,
    logs: receipt.logs.map(log => {
      if (log.topics[0] !== EVENT_TOPICS.Transfer) return log;
      const forgedAmount = (BigInt(log.data) + 1n).toString(16).padStart(64, '0');
      return { ...log, data: '0x' + forgedAmount };
    })
  });

  let caught = null;
  try { await driveAgentExecute(agent, executeOperationId(run), 25); }
  catch (error) { caught = error; }
  assert.ok(caught, 'execute must not succeed against a forged receipt');
  assert.ok(['SEMANTIC_CHECK_FAILED', 'SOURCE_DISAGREEMENT'].includes(caught.code), JSON.stringify({ code: caught.code, details: caught.details }));

  const stepView = agent.view().runs[0].steps.find(step => step.step === 'execute');
  assert.notEqual(stepView.status, 'verified');
  assert.notEqual(stepView.journalState, 'semantically_verified');
  // The real chain transfer happened once (only the observed receipt was
  // forged); verification correctly refuses to report it as proven.
  const balancesAfter = tokenBalances(env);
  assert.equal(balancesAfter.principal, balancesBefore.principal - amount);
  assert.equal(agentTransactionCount(env), 1);
});

// ---------------------------------------------------------------------------
// 14. Nonce conflict from a foreign agent transaction

test('a pending foreign agent transaction stops execute without a verified transfer', async () => {
  const env = environment();
  const { run } = await setupToAwaitingAgent(env);
  const agent = agentOf(env);
  const balancesBefore = tokenBalances(env);

  // A transaction from the agent address, signed outside Mandate Desk,
  // consumes nonce 0 and sits in the mempool before execute is prepared.
  const foreign = {
    chainId: env.proposal.chainId, from: env.proposal.agent, to: env.proposal.recipient.address,
    value: '0', data: '0x', nonce: '0', gasLimit: '21000', type: 2,
    maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000'
  };
  const signedForeign = signLiveTransaction(foreign, env.gateway.keys.agent);
  env.chain.register(signedForeign.signedTransaction, foreign, signedForeign.transactionHash);
  env.chain.accept(signedForeign.signedTransaction);

  let caught = null;
  try { await driveAgentExecute(agent, executeOperationId(run), 3); }
  catch (error) { caught = error; }
  assert.ok(caught, 'execute must stop rather than proceed around the foreign pending transaction');
  const allowed = ['PENDING_TRANSACTION_EXISTS', 'UNRESOLVED_EARLIER_TRANSACTION', 'NONCE_CONFLICT', 'SIMULATION_REVERTED'];
  assert.ok(allowed.includes(caught.code), JSON.stringify({ code: caught.code, details: caught.details }));

  const stepView = agent.view().runs[0].steps.find(step => step.step === 'execute');
  assert.notEqual(stepView.journalState, 'semantically_verified');
  assert.deepEqual(tokenBalances(env), balancesBefore);
});

// ---------------------------------------------------------------------------
// 15. No simulation fallback

test('a stopped live run never creates or changes the synthetic MDT store file', async () => {
  const env = environment();
  const { owner, run } = await ownerApproved(env);
  env.gateway.faults.prepare = ['PAYMENT_REQUIRED'];
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(owner.view().runs[0].stop.code, 'PAYMENT_REQUIRED');

  const storeFile = path.join(env.dir, 'state.json');
  const storeDataDir = path.join(env.dir, 'data');
  assert.equal(fs.existsSync(storeFile), false);
  assert.equal(fs.existsSync(storeDataDir), false);
});

// ---------------------------------------------------------------------------
// 16. Role denial

test('an owner workspace cannot execute and an agent workspace cannot perform owner actions', async () => {
  const env = environment();
  const owner = ownerOf(env);
  const agent = agentOf(env);
  const fakeRunId = 'live_' + 'a'.repeat(32);

  await assert.rejects(owner.agentExecute({ operationId: `${fakeRunId}_execute` }), error => error.code === 'ROLE_DENIED');

  await assert.rejects(agent.prepareRun(), error => error.code === 'ROLE_DENIED');
  assert.throws(() => agent.approveRun({ runId: fakeRunId, approvalSha256: 'a'.repeat(64) }), error => error.code === 'ROLE_DENIED');
  await assert.rejects(agent.startOwnerSetup({ runId: fakeRunId }), error => error.code === 'ROLE_DENIED');
  await assert.rejects(agent.startOwnerRevocation({ runId: fakeRunId }), error => error.code === 'ROLE_DENIED');
  await assert.rejects(agent.startCleanup({ runId: fakeRunId }), error => error.code === 'ROLE_DENIED');
});

// ---------------------------------------------------------------------------
// 17. Cleanup after a stop between grant and execute

test('cleanup after a stop between grant and execute revokes the mandate and resets the allowance', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  assert.equal(owner.view().runs[0].status, 'awaiting-agent');
  assert.equal(env.chain.state.mandate.revoked, false);
  assert.notEqual(env.chain.state.allowance, 0n);

  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);

  const view = owner.view().runs[0];
  assert.equal(view.status, 'stopped');
  assert.equal(view.cleanup.revokedByCleanup, true);
  assert.equal(view.cleanup.allowanceResetByCleanup, true);
  assert.equal(view.cleanup.mandateRevoked, true);
  assert.equal(view.cleanup.allowance, '0');
  assert.equal(env.chain.state.mandate.revoked, true);
  assert.equal(env.chain.state.allowance, 0n);
  assert.equal(agentTransactionCount(env), 0);
});
