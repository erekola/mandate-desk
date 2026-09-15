// Live Sepolia adapter. It runs one approved write at a time through the
// existing validators: fresh reads from two RPC sources, a Brickken
// client-signed preparation or a locally built envelope for the named RPC
// route, the complete pre-signature check, the bounded signer, broadcast,
// receipt tracking and the semantic postcheck on block-bound state. Each state
// change is written to the live journal before the next network action, so a
// timeout or restart resumes the same transaction identity instead of creating
// a new transfer. It never pays, never falls back to the simulation and never
// signs a replacement.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { SEPOLIA_CHAIN_ID, TRANSFER_FROM_ACTION, TRANSFER_FROM_SELECTOR, canonicalJson, sha256Canonical } from './brickken-intent.mjs';
import { EMPTY_METADATA } from './brickken-lifecycle.mjs';
import * as plan from './brickken-live-plan.mjs';
import { BrickkenJournalError, LIVE_SIGNER_SOURCE, livePostcheckKind } from './brickken-journal.mjs';
import { parseRamsPrepareResponse } from './brickken-prepare.mjs';
import { SEPOLIA_RPC_ENDPOINTS, SepoliaRpc, SepoliaRpcError, toPostcheckReceipt } from './brickken-rpc.mjs';
import { MAX_SEND_ATTEMPTS, SEND_ATTEMPT_WINDOW_MS, decodeSignedLiveTransaction } from './brickken-live-signer.mjs';
import {
  verifyApprovePostcheck,
  verifyExecutePostcheck,
  verifyGrantPostcheck,
  verifyRevokePostcheck,
  verifySetActionPostcheck
} from './brickken-postcheck.mjs';

// SHA-256 of the deployed runtime code read at Sepolia block 11704475 on
// 2026-09-14; the executor, registry and provider values equal the earlier
// public observation at block 0xb28d28. A change stops the run before any write.
export const LIVE_CODE_SHA256 = Object.freeze({
  executor: '830b7ced51f21b357e415ac325b5bf69fe717224175e10f1531d12108cac59e6',
  registry: '0542a93962339c2add74b82b4e4792f905b5ef2c02c000cb6e92056ee90b888f',
  complianceProvider: '604582dc8d183153d992d78316ec816a3fce6090612bee6d8026b004787a4b62',
  token: '846efa39d1689bdcffea1cdabe788d0b6f81050c0667ad6444e722aed27f7e86'
});
export const MIN_PRIORITY_FEE_WEI = 1_000_000_000n;
const RESEND_UNCERTAIN_AFTER_MS = 30_000;
const RESEND_BROADCAST_AFTER_MS = 180_000;
// Identical-bytes resends are bounded per time window on both routes. The
// journal keeps every attempt as the audit count; only the attempts inside the
// window count against the budget, and while the budget is used the step is
// still tracked by reads, so a short outage never locks a signed step for good.
export const BROADCAST_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
export const MAX_BROADCAST_ATTEMPTS_PER_WINDOW = 5;
const SIGNER_RESPONSE_LIMIT = 256 * 1024;
const BLOCK_WAIT_ATTEMPTS = 12;
const LIVE_OBSERVATION = Object.freeze({ observationSource: 'sepolia-rpc-block-bound' });
// Cleanup revokes a mandate that may already be non-executable (expired, frozen
// or spent); the verifier then records the prior executability instead of
// requiring it, and its report claims no revocation-effect demonstration.
const LIVE_CLEANUP_REVOCATION = Object.freeze({ observationSource: 'sepolia-rpc-block-bound', cleanupRevocation: true });

export class LiveAdapterError extends Error {
  constructor(code, details = {}) {
    super(code);
    this.name = 'LiveAdapterError';
    this.code = code;
    this.details = details;
  }
}
function fail(code, details = {}) { throw new LiveAdapterError(code, details); }
function iso(milliseconds) { return new Date(milliseconds).toISOString(); }
function sha256Hex(value) { return createHash('sha256').update(value).digest('hex'); }
function codeHash(code) { return sha256Hex(Buffer.from(code.slice(2), 'hex')); }
// The Brickken route uses the signer's own send budget so the adapter never asks
// for a send the signer would refuse; the RPC route uses the adapter's budget.
function attemptBudget(route) {
  return route === 'brickken-api'
    ? { limit: MAX_SEND_ATTEMPTS, windowMs: SEND_ATTEMPT_WINDOW_MS }
    : { limit: MAX_BROADCAST_ATTEMPTS_PER_WINDOW, windowMs: BROADCAST_ATTEMPT_WINDOW_MS };
}
function recentAttemptTimes(record, nowMs) {
  const { windowMs } = attemptBudget(record.route);
  const times = record.broadcast?.attemptsAt ?? (record.broadcast?.lastAttemptAt ? [record.broadcast.lastAttemptAt] : []);
  return times.filter(at => nowMs - Date.parse(at) < windowMs);
}
// The time the oldest attempt inside the window leaves it, or null while the budget has room.
export function broadcastBackoffUntil(record, nowMs) {
  const { limit, windowMs } = attemptBudget(record.route);
  const recent = recentAttemptTimes(record, nowMs);
  if (recent.length < limit) return null;
  return iso(Math.min(...recent.map(at => Date.parse(at))) + windowMs);
}

// Converts lower-level failures into a coded result that names the layer
// that refused. Unknown errors keep a fixed code and never echo their text.
export function classifyLiveError(error, step = null) {
  if (error instanceof LiveAdapterError) return error;
  // The workspace's ownership and code identity gates throw their own error type
  // inside the executor; their code and details are kept, never folded into INTERNAL.
  if (error?.name === 'BrickkenWorkspaceError' && typeof error.code === 'string') {
    return new LiveAdapterError(error.code, { layer: 'workspace', step, ...(error.details && typeof error.details === 'object' ? error.details : {}) });
  }
  if (error instanceof SepoliaRpcError) return new LiveAdapterError(error.code, { layer: 'rpc', step, method: error.method });
  if (error instanceof BrickkenJournalError) return new LiveAdapterError(error.code, { layer: 'journal', step });
  if (error instanceof plan.BrickkenLivePlanError) return new LiveAdapterError(error.code, { layer: 'local-validation', step });
  return new LiveAdapterError('INTERNAL', { layer: 'adapter', step });
}

export function createLiveRpcs({ fetchImpl = globalThis.fetch } = {}) {
  if (canonicalJson(SEPOLIA_RPC_ENDPOINTS) !== canonicalJson(plan.LIVE_READ_ENDPOINTS)) fail('ENDPOINT_CONFIGURATION', { layer: 'local-validation' });
  return Object.freeze({
    primary: new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl }),
    secondary: new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.secondary, fetchImpl })
  });
}

export function chooseFees(proposal, baseFeePerGas, suggestedPriorityFee) {
  const capFee = BigInt(proposal.fees.maxFeePerGas);
  const capPriority = BigInt(proposal.fees.maxPriorityFeePerGas);
  let priority = BigInt(suggestedPriorityFee);
  if (priority < MIN_PRIORITY_FEE_WEI) priority = MIN_PRIORITY_FEE_WEI;
  if (priority > capPriority) priority = capPriority;
  const base = BigInt(baseFeePerGas);
  // Stop instead of submitting a transaction that could stall under the cap.
  if (base * 12n / 10n + priority > capFee) fail('FEE_CEILING_REACHED', { layer: 'chain', baseFeePerGas: base.toString() });
  let maxFee = base * 2n + priority;
  if (maxFee > capFee) maxFee = capFee;
  return Object.freeze({ maxPriorityFeePerGas: priority.toString(), maxFeePerGas: maxFee.toString() });
}

export function chooseGasLimit(proposal, step, estimate) {
  const cap = BigInt(proposal.gasLimitCaps[step]);
  const estimated = BigInt(estimate);
  if (estimated > cap) fail('GAS_CEILING_REACHED', { layer: 'chain', step, estimate: estimated.toString() });
  let limit = (estimated * 125n + 99n) / 100n;
  if (limit > cap) limit = cap;
  if (limit < 21_000n) limit = 21_000n;
  return limit.toString();
}

// ---------------------------------------------------------------------------
// Signer client

const BRICKKEN_LAYER_CODES = new Set([
  'PAYMENT_REQUIRED', 'AUTHORIZATION_DENIED', 'RATE_LIMITED', 'HTTP_REJECTED', 'HTTP_TIMEOUT', 'NETWORK_FAILED',
  'HTTP_FAILED', 'REDIRECT_REJECTED', 'RESPONSE_TOO_LARGE', 'RESPONSE_INVALID', 'PREPARATION_REJECTED',
  'PAYMENT_REVIEW_REQUIRED', 'MODE_REJECTED', 'SEND_RESPONSE_UNREADABLE'
]);

export class LiveSignerClient {
  constructor({ dataDirectory, role, fetchImpl = globalThis.fetch }) {
    if (!['owner', 'agent'].includes(role) || typeof fetchImpl !== 'function' || typeof dataDirectory !== 'string') {
      fail('CONFIGURATION', { layer: 'local-validation' });
    }
    this.role = role;
    this.liveDirectory = path.join(dataDirectory, 'live');
    this.fetchImpl = fetchImpl;
  }

  #endpoint() {
    try {
      const endpoint = JSON.parse(fs.readFileSync(path.join(this.liveDirectory, 'signer-endpoint.json'), 'utf8'));
      const token = fs.readFileSync(path.join(this.liveDirectory, `signer-${this.role}.token`), 'utf8');
      if (endpoint?.kind !== 'mandate-desk-live-signer-endpoint' || !Number.isSafeInteger(endpoint.port) ||
          endpoint.port < 1024 || endpoint.port > 65535 || !/^[a-f0-9]{64}$/.test(token) ||
          !/^[a-f0-9]{64}$/.test(endpoint.approvalSha256 ?? '')) throw new Error('shape');
      return { port: endpoint.port, token, approvalSha256: endpoint.approvalSha256 };
    } catch {
      return fail('SIGNER_UNAVAILABLE', { layer: 'signer' });
    }
  }

  async #call(method, route, body, timeoutMs) {
    const { port, token } = this.#endpoint();
    let response;
    try {
      response = await this.fetchImpl(`http://127.0.0.1:${port}${route}`, {
        method,
        headers: body === undefined
          ? { authorization: `Bearer ${token}` }
          : { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs)
      });
    } catch (error) {
      // A timed-out request may already have reached Brickken; a refused one did not.
      if (error?.name === 'TimeoutError' || error?.name === 'AbortError') fail('SIGNER_TIMEOUT', { layer: 'signer' });
      fail('SIGNER_UNAVAILABLE', { layer: 'signer' });
    }
    let json;
    try {
      const text = await response.text();
      if (Buffer.byteLength(text, 'utf8') > SIGNER_RESPONSE_LIMIT) throw new Error('size');
      json = JSON.parse(text);
    } catch {
      fail('SIGNER_RESPONSE_INVALID', { layer: 'signer', status: response.status });
    }
    if (!response.ok) {
      const code = typeof json?.error === 'string' && /^[A-Z0-9_]{1,64}$/.test(json.error) ? json.error : 'SIGNER_REJECTED';
      const details = json?.details && typeof json.details === 'object' ? {
        status: Number.isSafeInteger(json.details.status) ? json.details.status : null,
        apiErrorCode: typeof json.details.apiErrorCode === 'string' ? json.details.apiErrorCode : null
      } : {};
      fail(code, { layer: BRICKKEN_LAYER_CODES.has(code) ? 'brickken-api' : 'signer', signerStatus: response.status, ...details });
    }
    return json;
  }

  approvalSha256() { return this.#endpoint().approvalSha256; }
  status() { return this.#call('GET', '/v1/status', undefined, 5_000); }
  async prepare(step, body) {
    const result = await this.#call('POST', '/v1/prepare', { step, body }, 45_000);
    if (typeof result?.responseText !== 'string') fail('SIGNER_RESPONSE_INVALID', { layer: 'signer' });
    return result.responseText;
  }
  sign(step, transaction) { return this.#call('POST', '/v1/sign', { step, transaction }, 15_000); }
  send(step, txId, signedTransaction) { return this.#call('POST', '/v1/send', { step, txId, signedTransaction }, 45_000); }
  transactionStatus(step) { return this.#call('POST', '/v1/transaction-status', { step }, 20_000); }
}

// ---------------------------------------------------------------------------
// Block-bound reads

async function waitForBlock(rpc, blockHash, sleep) {
  for (let attempt = 0; attempt < BLOCK_WAIT_ATTEMPTS; attempt++) {
    const block = await rpc.getBlock({ blockHash });
    if (block) return block;
    await sleep(1_500);
  }
  return fail('SOURCE_LAGGING', { layer: 'rpc', endpoint: rpc.endpointName, blockHash });
}

async function readReturn(rpc, call, ref, from = null) {
  const result = await rpc.call(from ? { from, to: call.to, data: call.data } : { to: call.to, data: call.data }, ref);
  if (!result.ok) fail('READ_REVERTED', { layer: 'contract', to: call.to, revert: plan.decodeRevert(result.revertData) });
  return result.returnData;
}

async function readStateSet(proposal, rpc, ref) {
  const calls = plan.readCalls(proposal);
  // Sequential on purpose: the public endpoints rate-limit bursts.
  const allowance = await readReturn(rpc, calls.allowance(), ref);
  const principalToken = await readReturn(rpc, calls.balanceOf(proposal.principal), ref);
  const recipientToken = await readReturn(rpc, calls.balanceOf(proposal.recipient.address), ref);
  const mandate = await readReturn(rpc, calls.getMandate(), ref);
  const actionEnabled = await readReturn(rpc, calls.isActionEnabled(), ref);
  const frozen = await readReturn(rpc, calls.isFrozen(), ref);
  const action = await readReturn(rpc, calls.executorAction(), ref);
  return {
    allowance: plan.decodeUintReturn(allowance),
    principalTokenBalance: plan.decodeUintReturn(principalToken),
    recipientTokenBalance: plan.decodeUintReturn(recipientToken),
    mandate: plan.decodeMandateReturn(mandate),
    actionEnabled: plan.decodeBoolReturn(actionEnabled),
    agentFrozen: plan.decodeBoolReturn(frozen),
    executorAction: plan.decodeActionSpecReturn(action)
  };
}

function mandateActiveAt(mandate, timestamp) {
  return mandate !== null && mandate.revoked === false &&
    BigInt(mandate.validFrom) <= BigInt(timestamp) && BigInt(timestamp) < BigInt(mandate.validUntil);
}

function actionConfigured(action) {
  return action.supported === true && action.hasAmount === true && action.amountIndex === 2;
}

// Fresh start-of-run observation. It records what the run relies on and the
// blockers that stop it; it never changes chain state.
export async function readLivePreflight({ proposal, rpcs, now = () => Date.now(), sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  const { primary, secondary } = rpcs;
  const [primaryChain, secondaryChain] = await Promise.all([primary.chainId(), secondary.chainId()]);
  if (primaryChain !== SEPOLIA_CHAIN_ID || secondaryChain !== SEPOLIA_CHAIN_ID) fail('WRONG_CHAIN', { layer: 'rpc' });
  const block = await primary.getBlock('latest');
  await waitForBlock(secondary, block.hash, sleep);
  const ref = { blockHash: block.hash };
  const calls = plan.readCalls(proposal);
  const code = {};
  for (const [name, target] of Object.entries({
    executor: proposal.executor, registry: proposal.registry,
    complianceProvider: proposal.complianceProvider, token: proposal.token.address
  })) code[name] = codeHash(await primary.getCode(target, ref));
  const [rams, executorPrincipal, owner, recorder, decimals] = await Promise.all([
    readReturn(primary, calls.executorRams(), ref), readReturn(primary, calls.executorPrincipal(), ref),
    readReturn(primary, calls.executorOwner(), ref), readReturn(primary, calls.hasRecorderRole(), ref),
    readReturn(primary, calls.decimals(), ref)
  ]);
  const state = await readStateSet(proposal, primary, ref);
  const secondaryState = await readStateSet(proposal, secondary, ref);
  if (canonicalJson(state) !== canonicalJson(secondaryState)) fail('SOURCE_STATE_DISAGREEMENT', { layer: 'rpc' });
  const [principalWei, agentWei, principalLatest, principalPending, agentLatest, agentPending, priority] = await Promise.all([
    primary.getBalance(proposal.principal, ref), primary.getBalance(proposal.agent, ref),
    primary.getTransactionCount(proposal.principal, 'latest'), primary.getTransactionCount(proposal.principal, 'pending'),
    primary.getTransactionCount(proposal.agent, 'latest'), primary.getTransactionCount(proposal.agent, 'pending'),
    primary.maxPriorityFeePerGas()
  ]);
  const setActionNeeded = !actionConfigured(state.executorAction);
  const plannedWrites = plan.LIVE_WRITE_STEPS.filter(step => step !== 'setAction' || setActionNeeded);
  const estimates = {};
  const estimate = async (step, validFrom = null) => {
    const from = plan.stepSignerAddress(proposal, step);
    const to = plan.stepTarget(proposal, step);
    const data = plan.expectedCalldata(proposal, step, step === 'grant' ? { validFrom } : {});
    try { estimates[step] = await primary.estimateGas({ from, to, data }, 'latest'); }
    catch (error) {
      if (!(error instanceof SepoliaRpcError) || error.code !== 'ESTIMATE_REVERTED') throw error;
      const simulated = await primary.call({ from, to, data }, 'latest');
      estimates[step] = { reverted: true, revert: plan.decodeRevert(simulated.ok ? null : simulated.revertData) };
    }
  };
  if (setActionNeeded) await estimate('setAction');
  await estimate('approve');
  await estimate('grant', Number(block.timestamp));
  await estimate('approveReset');
  let fees = null;
  let feeBlocker = null;
  try { fees = chooseFees(proposal, block.baseFeePerGas, priority); } catch (error) { feeBlocker = classifyLiveError(error).code; }
  const worstCase = plan.requiredWei(proposal, plannedWrites);
  const atCurrentFees = { owner: 0n, agent: 0n };
  if (fees) {
    for (const step of plannedWrites) {
      atCurrentFees[plan.LIVE_STEP_SIGNER[step]] += BigInt(proposal.gasLimitCaps[step]) * BigInt(fees.maxFeePerGas);
    }
  }
  const blockers = [];
  const addBlocker = (code, detail = null) => blockers.push(detail === null ? { code } : { code, detail });
  for (const [name, expected] of Object.entries(LIVE_CODE_SHA256)) {
    if (code[name] !== expected) addBlocker('CONTRACT_CODE_CHANGED', name);
  }
  if (plan.decodeAddressReturn(rams) !== proposal.registry || plan.decodeAddressReturn(executorPrincipal) !== proposal.principal ||
      plan.decodeAddressReturn(owner) !== proposal.principal) addBlocker('EXECUTOR_BINDING');
  if (!plan.decodeBoolReturn(recorder)) addBlocker('EXECUTOR_NOT_RECORDER');
  if (plan.decodeUintReturn(decimals) !== '6') addBlocker('TOKEN_DECIMALS');
  // A supported action with other parameters would be silently overwritten by setAction; stop instead.
  if (state.executorAction.supported && setActionNeeded) addBlocker('EXECUTOR_ACTION_UNEXPECTED');
  if (state.allowance !== '0') addBlocker('ALLOWANCE_NOT_ZERO', state.allowance);
  if (state.mandate !== null && state.mandate.revoked === false) addBlocker('MANDATE_NOT_REVOKED');
  if (state.agentFrozen) addBlocker('AGENT_FROZEN');
  if (principalLatest !== principalPending) addBlocker('OWNER_PENDING_TRANSACTION');
  if (agentLatest !== agentPending) addBlocker('AGENT_PENDING_TRANSACTION');
  if (BigInt(state.principalTokenBalance) < BigInt(proposal.limits.minimumPrincipalTokenBalance)) {
    addBlocker('PRINCIPAL_TOKEN_BALANCE', state.principalTokenBalance);
  }
  if (feeBlocker) addBlocker(feeBlocker);
  if (fees && BigInt(principalWei) < atCurrentFees.owner) addBlocker('OWNER_GAS_FUNDING', principalWei);
  if (fees && BigInt(agentWei) < atCurrentFees.agent) addBlocker('AGENT_GAS_FUNDING', agentWei);
  for (const [step, value] of Object.entries(estimates)) {
    if (typeof value !== 'string') addBlocker('SIMULATION_REVERTED', step);
    else if (BigInt(value) > BigInt(proposal.gasLimitCaps[step])) addBlocker('GAS_CEILING_REACHED', step);
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'mandate-desk-live-preflight',
    observedAt: iso(now()),
    endpoints: { primary: SEPOLIA_RPC_ENDPOINTS.primary, secondary: SEPOLIA_RPC_ENDPOINTS.secondary },
    chainId: primaryChain,
    block: { number: block.number, hash: block.hash, timestamp: block.timestamp, baseFeePerGas: block.baseFeePerGas },
    secondaryBlockHashAgreed: true,
    codeSha256: code,
    executorBindings: {
      rams: plan.decodeAddressReturn(rams), principal: plan.decodeAddressReturn(executorPrincipal),
      owner: plan.decodeAddressReturn(owner), recorderRole: plan.decodeBoolReturn(recorder)
    },
    tokenDecimals: plan.decodeUintReturn(decimals),
    state,
    balancesWei: { owner: principalWei, agent: agentWei },
    nonces: { owner: { latest: principalLatest, pending: principalPending }, agent: { latest: agentLatest, pending: agentPending } },
    suggestedPriorityFeePerGas: priority,
    fees,
    gasEstimates: estimates,
    plannedWrites,
    requiredWei: {
      atCurrentFees: { owner: atCurrentFees.owner.toString(), agent: atCurrentFees.agent.toString() },
      atApprovedFeeCeiling: worstCase
    },
    blockers
  });
}

// ---------------------------------------------------------------------------
// Read-only controls

function evaluateCall(proposal, call, result) {
  if (call.expect === 'success') return result.ok === true;
  if (call.expect === 'true' || call.expect === 'false') {
    return result.ok === true && plan.decodeBoolReturn(result.returnData) === (call.expect === 'true');
  }
  if (call.expect === 'revert:CannotExecute') {
    if (result.ok !== false) return false;
    const decoded = plan.decodeRevert(result.revertData);
    const amount = BigInt('0x' + call.data.slice(10 + 64 * 3 + 8 + 64 * 2, 10 + 64 * 3 + 8 + 64 * 3)).toString();
    return decoded.name === 'CannotExecute' && decoded.args?.agent === proposal.agent &&
      decoded.args?.target === proposal.token.address && decoded.args?.selector === TRANSFER_FROM_SELECTOR &&
      decoded.args?.amount === amount;
  }
  return false;
}

function controlConditions(proposal, controlId, facts, timestamp) {
  const m = facts.mandate;
  const used = m ? BigInt(m.cumulativeUsed) : 0n;
  const maxTx = BigInt(proposal.limits.maxTransactionValue);
  const maxCum = BigInt(proposal.limits.maxCumulativeValue);
  const conditions = [];
  const hold = (id, value) => conditions.push({ id, holds: Boolean(value) });
  const inWindow = m !== null && BigInt(m.validFrom) <= BigInt(timestamp) && BigInt(timestamp) < BigInt(m.validUntil);
  const common = () => {
    hold('mandate-exists', m !== null);
    hold('within-validity-window', inWindow);
    hold('agent-not-frozen', facts.agentFrozen === false);
    hold('action-enabled', facts.actionEnabled === true);
    hold('executor-action-configured', actionConfigured(facts.executorAction));
  };
  switch (controlId) {
    case 'control-transaction-cap': {
      const over = BigInt(proposal.amounts.overTransactionCapProbe);
      common();
      hold('not-revoked', m?.revoked === false);
      hold('cumulative-unused', used === 0n);
      hold('over-amount-exceeds-transaction-cap', over > maxTx);
      hold('over-amount-within-cumulative-cap', over <= maxCum);
      hold('balance-covers-over-amount', BigInt(facts.principalTokenBalance) >= over);
      hold('allowance-covers-over-amount', BigInt(facts.allowance) >= over);
      break;
    }
    case 'control-cumulative-cap': {
      const allowed = BigInt(proposal.amounts.cumulativeAllowedProbe);
      const denied = BigInt(proposal.amounts.cumulativeDeniedProbe);
      common();
      hold('not-revoked', m?.revoked === false);
      hold('cumulative-used-equals-execute', used === BigInt(proposal.amounts.execute));
      hold('both-amounts-within-transaction-cap', allowed <= maxTx && denied <= maxTx);
      hold('allowed-amount-fits-remaining-cap', used + allowed <= maxCum);
      hold('denied-amount-exceeds-remaining-cap', used + denied > maxCum);
      break;
    }
    case 'control-before-revoke':
    case 'control-after-revoke': {
      const probe = BigInt(proposal.amounts.revocationProbe);
      common();
      hold(controlId === 'control-before-revoke' ? 'not-revoked' : 'revoked', controlId === 'control-before-revoke' ? m?.revoked === false : m?.revoked === true);
      hold('probe-within-transaction-cap', probe <= maxTx);
      hold('probe-fits-remaining-cumulative-cap', used + probe <= maxCum);
      hold('balance-covers-probe', BigInt(facts.principalTokenBalance) >= probe);
      hold('allowance-covers-probe', BigInt(facts.allowance) >= probe);
      break;
    }
    default:
      fail('CONTROL', { layer: 'local-validation' });
  }
  return conditions;
}

const CONTROL_INTERPRETATION = Object.freeze({
  'control-transaction-cap': 'Both calls use the same block. The allowed amount succeeds and the larger amount reverts with CannotExecute while balance, allowance, cumulative cap, validity, freeze and action checks hold, so the denial is attributed to the per-transfer cap. The larger request is an unsigned probe and was never a transaction.',
  'control-cumulative-cap': 'Both AgentMandate.canExecute calls use the same block after the executed transfer. The smaller amount is allowed and the larger amount is denied while both fit the per-transfer cap. This proves the RAMS cumulative gate only; the executor token allowance would also limit a transfer.',
  'control-before-revoke': 'The exact revocation probe calldata succeeds as a read-only call before revocation.',
  'control-after-revoke': 'The same calldata, sender, target and value revert with CannotExecute after revocation while balance, allowance, caps, validity, freeze and action checks still hold, so the denial is attributed to revocation. No rejected transaction was sent.'
});

export async function runLiveControl({ proposal, rpcs, controlId, now = () => Date.now(), sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  const { primary, secondary } = rpcs;
  const block = await primary.getBlock('latest');
  await waitForBlock(secondary, block.hash, sleep);
  const ref = { blockHash: block.hash };
  const calls = plan.controlCalls(proposal, controlId);
  const results = [];
  for (const call of calls) {
    const input = call.from ? { from: call.from, to: call.to, data: call.data } : { to: call.to, data: call.data };
    const primaryResult = await primary.call(input, ref);
    const secondaryResult = await secondary.call(input, ref);
    results.push({
      label: call.label, from: call.from, to: call.to, value: call.value, data: call.data, expect: call.expect,
      result: primaryResult,
      decodedRevert: primaryResult.ok ? null : plan.decodeRevert(primaryResult.revertData),
      secondaryAgrees: canonicalJson(primaryResult) === canonicalJson(secondaryResult),
      passed: evaluateCall(proposal, call, primaryResult)
    });
  }
  const facts = await readStateSet(proposal, primary, ref);
  const secondaryFacts = await readStateSet(proposal, secondary, ref);
  const conditions = controlConditions(proposal, controlId, facts, block.timestamp);
  const allowedLegPassed = results.filter(item => item.expect === 'success' || item.expect === 'true').every(item => item.passed);
  const passed = results.every(item => item.passed && item.secondaryAgrees) && conditions.every(item => item.holds) &&
    canonicalJson(facts) === canonicalJson(secondaryFacts);
  return Object.freeze({
    schemaVersion: 1,
    kind: 'mandate-desk-live-control',
    controlId,
    observedAt: iso(now()),
    block: { number: block.number, hash: block.hash, timestamp: block.timestamp },
    broadcast: false,
    transactionHash: null,
    calls: results,
    facts,
    secondaryFactsAgree: canonicalJson(facts) === canonicalJson(secondaryFacts),
    conditions,
    allowedLegPassed,
    passed,
    // A failed allowed leg means the denied leg proves nothing about caps or revocation.
    interpretation: passed ? CONTROL_INTERPRETATION[controlId] : (allowedLegPassed
      ? 'The control did not meet every expectation; no conclusion is drawn.'
      : 'The allowed request did not succeed, so the denied request is not evidence of the cap or revocation.')
  });
}

// ---------------------------------------------------------------------------
// Semantic postcheck inputs

function semanticsFor(proposal, step, record) {
  switch (step) {
    case 'setAction':
      return { executor: proposal.executor, owner: proposal.principal, selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: true, amountIndex: 2 };
    case 'approve':
    case 'approveReset':
      return { token: proposal.token.address, owner: proposal.principal, spender: proposal.executor, amount: step === 'approve' ? proposal.limits.allowance : '0' };
    case 'grant': {
      const validFrom = plan.grantValidFrom(record.transaction.data);
      return {
        registry: proposal.registry, agent: proposal.agent, principal: proposal.principal,
        complianceProvider: proposal.complianceProvider, asset: proposal.token.address,
        validFrom: String(validFrom), validUntil: String(validFrom + proposal.mandateValiditySeconds),
        identityRef: proposal.identityRef, metadata: EMPTY_METADATA, action: TRANSFER_FROM_ACTION,
        maxTransactionValue: proposal.limits.maxTransactionValue, maxCumulativeValue: proposal.limits.maxCumulativeValue
      };
    }
    case 'execute': {
      const amount = BigInt(proposal.amounts.execute);
      return {
        registry: proposal.registry, executor: proposal.executor, token: proposal.token.address,
        agent: proposal.agent, principal: proposal.principal, recipient: proposal.recipient.address,
        action: TRANSFER_FROM_ACTION, amount: amount.toString(),
        maxTransactionValue: proposal.limits.maxTransactionValue, maxCumulativeValue: proposal.limits.maxCumulativeValue,
        canExecuteAfter: amount + amount <= BigInt(proposal.limits.maxCumulativeValue) &&
          amount + amount <= BigInt(proposal.limits.allowance)
      };
    }
    case 'revoke':
      return { registry: proposal.registry, agent: proposal.agent, principal: proposal.principal, revokedBy: proposal.principal };
    default:
      return fail('STEP', { layer: 'local-validation' });
  }
}

async function postcheckState(proposal, step, rpc, ref) {
  const calls = plan.readCalls(proposal);
  const read = call => readReturn(rpc, call, ref);
  switch (step) {
    case 'setAction':
      return { action: plan.decodeActionSpecReturn(await read(calls.executorAction())) };
    case 'approve':
    case 'approveReset':
      return { allowance: plan.decodeUintReturn(await read(calls.allowance())) };
    case 'grant':
      return {
        mandate: plan.decodeMandateReturn(await read(calls.getMandate())),
        actionEnabled: plan.decodeBoolReturn(await read(calls.isActionEnabled()))
      };
    case 'execute':
      return {
        principalBalance: plan.decodeUintReturn(await read(calls.balanceOf(proposal.principal))),
        recipientBalance: plan.decodeUintReturn(await read(calls.balanceOf(proposal.recipient.address))),
        allowance: plan.decodeUintReturn(await read(calls.allowance())),
        mandate: plan.decodeMandateReturn(await read(calls.getMandate())),
        canExecute: plan.decodeBoolReturn(await read(calls.canExecute(proposal.amounts.execute)))
      };
    case 'revoke':
      return {
        mandate: plan.decodeMandateReturn(await read(calls.getMandate())),
        actionEnabled: plan.decodeBoolReturn(await read(calls.isActionEnabled())),
        canExecute: plan.decodeBoolReturn(await read(calls.canExecute(proposal.amounts.revocationProbe)))
      };
    default:
      return fail('STEP', { layer: 'local-validation' });
  }
}

const VERIFIERS = Object.freeze({
  setAction: verifySetActionPostcheck,
  approve: verifyApprovePostcheck,
  grant: verifyGrantPostcheck,
  execute: verifyExecutePostcheck,
  revoke: verifyRevokePostcheck
});

// ---------------------------------------------------------------------------
// One write step

export class LiveStepExecutor {
  // notAfter is the run approval's expiry: after it nothing is prepared, signed
  // or sent again, and recorded bytes are only tracked by reads until a recovery
  // authorization exists. trackingOnly forces that read-only mode. cleanup
  // selects the cleanup revocation verifier. assertOwnership is called before
  // every action, and again right before every prepare, sign and send after the
  // awaits that precede them, so a displaced run lock stops the step instead of
  // continuing (A1-F03). assertCodeIdentity is called at the same points so a
  // changed source file stops the step before a signature or a send (N5).
  // semanticVerification false opens a tracking-only executor that follows a
  // recorded transaction to its receipt but never marks a semantic result: a
  // process that runs other bytes than the run was approved for may read the
  // chain, and a semantic claim is made only by the approved code (R2-F03).
  // assertControls(step) is called inside #sign, after the last nonce reads and
  // the decision whether to prepare again, right before signer.sign, so the
  // read-only controls the step rests on are read from both sources at the last
  // action boundary and not only when the phase began (ADV3-01, R3-F01). It is
  // a fresh two-source observation, not an atomic guarantee that the chain
  // cannot change after it.
  constructor({
    proposal, rpcs, signer, journal, approvalSha256,
    now = () => Date.now(),
    sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
    pollMs = 5_000,
    verifySignedTransaction = decodeSignedLiveTransaction,
    onEvidence = () => {},
    notAfter = null,
    trackingOnly = false,
    cleanup = false,
    semanticVerification = true,
    assertOwnership = () => {},
    assertCodeIdentity = () => {},
    assertControls = async () => {}
  }) {
    if (!/^[a-f0-9]{64}$/.test(approvalSha256 ?? '')) fail('CONFIGURATION', { layer: 'local-validation' });
    if (notAfter !== null && (typeof notAfter !== 'string' || !Number.isFinite(Date.parse(notAfter)))) fail('CONFIGURATION', { layer: 'local-validation' });
    if (typeof assertOwnership !== 'function' || typeof assertCodeIdentity !== 'function' || typeof assertControls !== 'function') {
      fail('CONFIGURATION', { layer: 'local-validation' });
    }
    this.proposal = proposal;
    this.rpcs = rpcs;
    this.signer = signer;
    this.journal = journal;
    this.approvalSha256 = approvalSha256;
    this.now = now;
    this.sleep = sleep;
    this.pollMs = pollMs;
    this.verifySignedTransaction = verifySignedTransaction;
    this.onEvidence = onEvidence;
    this.notAfter = notAfter;
    this.trackingOnly = trackingOnly === true;
    this.cleanup = cleanup === true;
    this.semanticVerification = semanticVerification !== false;
    if (!this.semanticVerification && !this.trackingOnly) fail('CONFIGURATION', { layer: 'local-validation' });
    this.assertOwnership = assertOwnership;
    this.assertCodeIdentity = assertCodeIdentity;
    this.assertControls = assertControls;
    this.requiredDepth = proposal.confirmations.stepProgression;
  }

  // Both write-capable gates in one call, used right before an external action.
  #beforeWrite() {
    this.assertOwnership();
    this.assertCodeIdentity();
  }

  // False once the approval expired or the executor was opened for tracking only.
  #writesAllowed() {
    return !this.trackingOnly && (this.notAfter === null || this.now() < Date.parse(this.notAfter));
  }

  async advance({ runId, step, deadlineMs = 120_000 }) {
    if (!plan.LIVE_WRITE_STEPS.includes(step) || typeof runId !== 'string' || !/^[A-Za-z0-9_-]{8,80}$/.test(runId)) {
      fail('STEP', { layer: 'local-validation', step });
    }
    const operationId = `${runId}_${step}`;
    const started = this.now();
    try {
      this.assertOwnership();
      let record = this.journal.find(operationId);
      if (!record) {
        // Nothing exists for this step yet; a new preparation needs an active approval
        // and every earlier write of the run at the required depth on both sources.
        if (!this.#writesAllowed()) fail('APPROVAL_EXPIRED', { layer: 'local-validation', step, notAfter: this.notAfter });
        const blocked = await this.#dependencyBlock(runId, step);
        if (blocked) { await this.sleep(this.pollMs); return this.#outcome(step, null, false, { operationId, waitingFor: blocked }); }
        record = await this.#prepare(step, operationId);
      }
      while (true) {
        this.assertOwnership();
        if (record.state === 'semantically_verified') return this.#outcome(step, record, true);
        if (record.state === 'reverted') {
          fail('TRANSACTION_REVERTED', { layer: 'contract', step, transactionHash: record.signed.ethereumTransactionHash });
        }
        if (this.now() - started > deadlineMs) return this.#outcome(step, record, false);
        switch (record.state) {
          case 'pending': {
            // Nothing is signed: a fresh signature after expiry would need a new approval,
            // and a signature is a dependent write, so the depth gate runs again here.
            if (!this.#writesAllowed()) fail('APPROVAL_EXPIRED', { layer: 'local-validation', step, notAfter: this.notAfter });
            const blocked = await this.#dependencyBlock(runId, step);
            if (blocked) { await this.sleep(this.pollMs); return this.#outcome(step, record, false, { waitingFor: blocked }); }
            record = await this.#sign(step, record); break;
          }
          case 'signed':
            // Recorded bytes that never left this process: sending them after expiry
            // needs a recovery authorization bound to exactly this hash and these bytes.
            if (!this.#writesAllowed()) {
              fail('RECOVERY_AUTHORIZATION_REQUIRED', {
                layer: 'local-validation', step, transactionHash: record.signed.ethereumTransactionHash,
                notAfter: this.notAfter, journalState: record.state, attempts: 0
              });
            }
            record = await this.#broadcast(step, record); break;
          case 'broadcast':
          case 'uncertain': record = await this.#track(step, record); break;
          case 'confirmed':
            // The receipt is recorded; the semantic result would be a claim by
            // this process's code, so a process without the approved identity
            // stops here and leaves the record confirmed (R2-F03).
            if (!this.semanticVerification) return this.#outcome(step, record, false, { waitingFor: { reason: 'CODE_IDENTITY_MISMATCH', journalState: record.state } });
            record = await this.#verify(step, record); break;
          default: fail('JOURNAL_STATE', { layer: 'journal', step });
        }
      }
    } catch (error) {
      throw classifyLiveError(error, step);
    }
  }

  // Re-reads the block of every verified write on both sources. The reading is
  // aggregated per source: a differing hash from either source withdraws the
  // confirmation so the step is tracked again, also when the other source has
  // no block at that height; a source without the block proves nothing, so the
  // state is kept and the stored depth becomes 0 (A1-F06). The depth stored on
  // a clean reading is the smaller of the two sources, and a verified write is
  // eligible to be built on only while both sources return the recorded hash
  // at the required depth (A1-F05). Each result says why a write is not.
  async recheck(operationIds) {
    const { primary, secondary } = this.rpcs;
    const results = [];
    for (const operationId of operationIds) {
      const record = this.journal.find(operationId);
      if (!record || !['confirmed', 'semantically_verified', 'reverted'].includes(record.state)) continue;
      const height = record.confirmation.blockNumber;
      const recorded = record.confirmation.blockHash;
      const [a, b, latestPrimary, latestSecondary] = await Promise.all([
        primary.getBlock({ blockNumber: height }), secondary.getBlock({ blockNumber: height }),
        primary.blockNumber(), secondary.blockNumber()
      ]);
      const depth = tip => Math.max(0, Number(BigInt(tip) - BigInt(height) + 1n));
      const confirmationsPrimary = a ? depth(latestPrimary) : 0;
      const confirmationsSecondary = b ? depth(latestSecondary) : 0;
      const differs = block => block !== null && block.hash !== recorded;
      const withdrawn = differs(a) || differs(b);
      const bothPresent = Boolean(a && b);
      const confirmations = withdrawn || !bothPresent ? 0 : Math.min(confirmationsPrimary, confirmationsSecondary);
      const next = this.journal.recheckConfirmation(operationId, {
        transactionHash: record.confirmation.transactionHash, blockNumber: height,
        blockHash: a?.hash ?? null, secondaryBlockHash: b?.hash ?? null,
        confirmations, checkedAt: iso(this.now())
      });
      const reason = withdrawn ? 'CONFIRMATION_WITHDRAWN'
        : !bothPresent ? 'SOURCE_MISSING_BLOCK'
          : confirmations < this.requiredDepth ? 'DEPTH_BELOW_THRESHOLD'
            : next.state !== 'semantically_verified' ? 'DEPENDENCY_UNSETTLED' : null;
      results.push(Object.freeze({
        operationId, state: next.state, confirmations, confirmationsPrimary, confirmationsSecondary,
        required: this.requiredDepth, sourcesAgreed: bothPresent && !withdrawn,
        // depthEligible: both sources return the recorded hash at the required depth; eligible adds the semantic verification.
        depthEligible: reason === null || reason === 'DEPENDENCY_UNSETTLED', eligible: reason === null, reason
      }));
    }
    return results;
  }

  // A fresh two-source reading of one write's eligibility to be built on.
  async progression(operationId) {
    const [result] = await this.recheck([operationId]);
    return result ?? Object.freeze({ operationId, state: this.journal.find(operationId)?.state ?? null, depthEligible: false, eligible: false, reason: 'DEPENDENCY_UNSETTLED', required: this.requiredDepth });
  }

  // Before a new dependent write (a preparation or a signature) every other
  // write of the run that already has a record must be settled: a verified one
  // must still read at the required depth from both sources right now, a
  // reverted one changed nothing, and anything else is unsettled. The run is a
  // sequence, so each new write is built on the state after all earlier ones.
  // Returns null when the write may proceed, otherwise the blocking reason.
  async #dependencyBlock(runId, step) {
    for (const other of plan.LIVE_WRITE_STEPS) {
      if (other === step) continue;
      const operationId = `${runId}_${other}`;
      const record = this.journal.find(operationId);
      if (!record || record.state === 'reverted') continue;
      // Outside cleanup every earlier write must be semantically verified; cleanup
      // may build on a confirmed write whose chain effect it attributes separately.
      const settled = this.cleanup ? ['confirmed', 'semantically_verified'] : ['semantically_verified'];
      if (!settled.includes(record.state)) {
        return { dependencyOperationId: operationId, reason: 'DEPENDENCY_UNSETTLED', journalState: record.state, required: this.requiredDepth };
      }
      const result = await this.progression(operationId);
      if (!result.depthEligible || !settled.includes(result.state)) {
        return {
          dependencyOperationId: operationId, reason: result.reason ?? 'DEPENDENCY_UNSETTLED', journalState: result.state, required: this.requiredDepth,
          confirmationsPrimary: result.confirmationsPrimary ?? null, confirmationsSecondary: result.confirmationsSecondary ?? null
        };
      }
    }
    return null;
  }

  #outcome(step, record, done, { operationId = record?.operationId ?? null, waitingFor = null } = {}) {
    return Object.freeze({
      step, operationId, done, state: record?.state ?? null, route: record?.route ?? null, apiTxId: record?.apiTxId ?? null,
      transactionHash: record?.signed?.ethereumTransactionHash ?? null,
      blockNumber: record?.confirmation?.blockNumber ?? null,
      blockHash: record?.confirmation?.blockHash ?? null,
      semanticallyVerified: record?.state === 'semantically_verified',
      attempts: record?.broadcast?.attempts ?? 0,
      backoffUntil: record?.broadcast ? broadcastBackoffUntil(record, this.now()) : null,
      trackingOnly: !this.#writesAllowed(),
      waitingFor
    });
  }

  async #freshNonceAndFees(step, from) {
    const { primary, secondary } = this.rpcs;
    const [latest, pending, secondaryLatest, block, priority] = await Promise.all([
      primary.getTransactionCount(from, 'latest'), primary.getTransactionCount(from, 'pending'),
      secondary.getTransactionCount(from, 'latest'), primary.getBlock('latest'), primary.maxPriorityFeePerGas()
    ]);
    if (latest !== pending) fail('PENDING_TRANSACTION_EXISTS', { layer: 'chain', step, from });
    if (secondaryLatest !== latest) fail('SOURCE_DISAGREEMENT', { layer: 'rpc', step, field: 'nonce' });
    for (const other of this.journal.list()) {
      if (other.transaction.from === from && other.signed && !['semantically_verified', 'confirmed', 'reverted'].includes(other.state) &&
          BigInt(other.transaction.nonce) >= BigInt(latest)) {
        fail('UNRESOLVED_EARLIER_TRANSACTION', { layer: 'journal', step, operationId: other.operationId });
      }
    }
    return { nonce: latest, block, fees: chooseFees(this.proposal, block.baseFeePerGas, priority) };
  }

  async #prepare(step, operationId) {
    const proposal = this.proposal;
    const { primary } = this.rpcs;
    const from = plan.stepSignerAddress(proposal, step);
    const to = plan.stepTarget(proposal, step);
    const { nonce, block, fees } = await this.#freshNonceAndFees(step, from);
    const validFrom = step === 'grant' ? Number(block.timestamp) : null;
    const data = plan.expectedCalldata(proposal, step, step === 'grant' ? { validFrom } : {});
    let estimate;
    try {
      estimate = await primary.estimateGas({ from, to, data }, 'latest');
    } catch (error) {
      if (error instanceof SepoliaRpcError && error.code === 'ESTIMATE_REVERTED') {
        const simulated = await primary.call({ from, to, data }, 'latest');
        fail('SIMULATION_REVERTED', { layer: 'contract', step, revert: plan.decodeRevert(simulated.ok ? null : simulated.revertData) });
      }
      throw error;
    }
    const gasLimit = chooseGasLimit(proposal, step, estimate);
    const balance = await primary.getBalance(from, 'latest');
    const requireFunds = tx => {
      if (BigInt(balance) < BigInt(tx.gasLimit) * BigInt(tx.maxFeePerGas)) {
        fail('GAS_FUNDING', { layer: 'chain', step, balanceWei: balance });
      }
    };
    const createdAt = iso(this.now());
    let binding;
    let x402Quote = null;
    if (plan.LIVE_STEP_ROUTE[step] === 'sepolia-rpc') {
      const tx = plan.checkLiveTransaction(proposal, step, {
        chainId: SEPOLIA_CHAIN_ID, from, to, value: '0', data, nonce, gasLimit, type: 2, ...fees
      }, { nonce });
      requireFunds(tx);
      binding = {
        operationId, operationKind: step, route: 'sepolia-rpc', apiTxId: null,
        preparationHash: sha256Canonical({ kind: 'mandate-desk-live-rpc-preparation', step, transaction: tx, estimate }),
        transaction: tx, createdAt
      };
    } else {
      const body = plan.facadeBody(proposal, step, { nonce, gasLimit, validFrom });
      // The reads above awaited; ownership and the code identity are checked again before the write-capable call.
      this.#beforeWrite();
      const responseText = await this.signer.prepare(step, body);
      let parsed;
      try { parsed = parseRamsPrepareResponse(responseText); }
      catch (error) { fail('PREPARATION_REJECTED', { layer: 'brickken-api', step, check: error?.code ?? null }); }
      // The quote is evidence of what the API priced, never a payment and never part of the preparation hash.
      x402Quote = parsed.x402Quote ?? null;
      let tx;
      try { tx = plan.checkLiveTransaction(proposal, step, parsed.transaction, { nonce }); }
      catch (error) { fail('PREPARED_TRANSACTION_REJECTED', { layer: 'local-validation', step, check: error?.code ?? null }); }
      const mismatch = (step === 'grant' && plan.grantValidFrom(tx.data) !== validFrom) ? 'GRANT_WINDOW'
        : (parsed.contractAddress !== null && parsed.contractAddress !== to) ? 'CONTRACT_ADDRESS'
          : BigInt(tx.gasLimit) < BigInt(estimate) ? 'GAS_BELOW_ESTIMATE'
            : BigInt(tx.maxFeePerGas) < BigInt(block.baseFeePerGas) ? 'FEE_BELOW_BASE_FEE' : null;
      if (mismatch) fail('PREPARED_TRANSACTION_REJECTED', { layer: 'local-validation', step, check: mismatch });
      requireFunds(tx);
      binding = {
        operationId, operationKind: step, route: 'brickken-api', apiTxId: parsed.txId,
        preparationHash: sha256Canonical({
          kind: 'mandate-desk-live-brickken-preparation', step, txId: parsed.txId,
          transactionsContainerShape: parsed.transactionsContainerShape, mode: parsed.mode,
          contractAddress: parsed.contractAddress, transaction: tx, estimate
        }),
        transaction: tx, createdAt
      };
    }
    const existing = this.journal.find(operationId);
    const record = existing ? this.journal.replacePending(binding) : this.journal.createPending(binding);
    this.onEvidence(`${operationId}-preparation`, {
      operationId, step, route: binding.route, apiTxId: binding.apiTxId, preparationHash: binding.preparationHash,
      transaction: binding.transaction, gasEstimate: estimate, preparedAt: createdAt,
      observedBlock: { number: block.number, hash: block.hash, baseFeePerGas: block.baseFeePerGas },
      x402Quote
    });
    return record;
  }

  async #sign(step, record) {
    const { primary } = this.rpcs;
    const from = record.transaction.from;
    const [latest, pending] = await Promise.all([
      primary.getTransactionCount(from, 'latest'), primary.getTransactionCount(from, 'pending')
    ]);
    const nowSeconds = Math.floor(this.now() / 1000);
    const staleWindow = step === 'grant' &&
      Math.abs(plan.grantValidFrom(record.transaction.data) - nowSeconds) > plan.GRANT_START_TOLERANCE_SECONDS - 60;
    // Nothing is signed yet, so a stale nonce or window is replaced by a fresh preparation.
    if (latest !== record.transaction.nonce || pending !== latest || staleWindow) return this.#prepare(step, record.operationId);
    plan.checkLiveTransaction(this.proposal, step, record.transaction, { nonce: latest });
    // The last reads before the signature are done: the controls this step rests
    // on are read from both sources now (R3-F01), and then ownership and the code
    // identity are checked once more, so nothing awaited stands between these
    // checks and the request to the signer.
    await this.assertControls(step);
    this.#beforeWrite();
    const result = await this.signer.sign(step, record.transaction);
    if (typeof result?.signedTransaction !== 'string') fail('SIGNER_RESPONSE_INVALID', { layer: 'signer', step });
    try {
      return this.journal.recordSigned(record.operationId, {
        source: LIVE_SIGNER_SOURCE, approvalSha256: this.approvalSha256,
        signedTransaction: result.signedTransaction, signedAt: iso(this.now())
      }, this.verifySignedTransaction);
    } catch (error) {
      if (error instanceof BrickkenJournalError) fail('SIGNED_TRANSACTION_REJECTED', { layer: 'signer', step, check: error.code });
      throw error;
    }
  }

  async #broadcast(step, record) {
    const bytes = record.signed.signedTransaction;
    const attemptedAt = iso(this.now());
    const persist = (result, relayTransactionHash) => this.journal.recordBroadcast(record.operationId, bytes, { result, attemptedAt, relayTransactionHash });
    // Ownership and the code identity are checked right before the network call.
    // Once the send has started its result is journaled whatever happens to the
    // lock meanwhile: bytes that may have reached the network are never forgotten.
    this.#beforeWrite();
    if (record.route === 'sepolia-rpc') {
      // The per-window budget is enforced where a resend is decided (#track).
      try {
        const hash = await this.rpcs.primary.sendRawTransaction(bytes);
        return persist('accepted', hash);
      } catch (error) {
        if (!(error instanceof SepoliaRpcError)) throw error;
        if (error.code === 'ALREADY_KNOWN') return persist('accepted', null);
        if (['INSUFFICIENT_FUNDS', 'FEE_TOO_LOW', 'REPLACEMENT_UNDERPRICED'].includes(error.code)) {
          fail('BROADCAST_REJECTED', { layer: 'rpc', step, rpcCode: error.code });
        }
        // Timeouts, transport failures and unclassified rejections may still have reached the network.
        return persist('uncertain', null);
      }
    }
    try {
      const sent = await this.signer.send(step, record.apiTxId, bytes);
      if (typeof sent?.relayTransactionHash !== 'string' || !/^0x[0-9a-f]{64}$/.test(sent.relayTransactionHash)) {
        return persist('uncertain', null);
      }
      return persist('accepted', sent.relayTransactionHash);
    } catch (error) {
      const classified = classifyLiveError(error, step);
      const status = classified.details?.status ?? null;
      if (['SIGNER_TIMEOUT', 'HTTP_TIMEOUT', 'NETWORK_FAILED', 'HTTP_FAILED', 'SEND_RESPONSE_UNREADABLE', 'RESPONSE_INVALID', 'RESPONSE_TOO_LARGE'].includes(classified.code) ||
          (classified.code === 'HTTP_REJECTED' && Number.isSafeInteger(status) && status >= 500)) {
        return persist('uncertain', null);
      }
      if (classified.code === 'SEND_ATTEMPTS_EXHAUSTED') {
        // The signer's own window is used up (its log may hold attempts a crash kept
        // out of the journal): keep tracking at the poll rate, never in a tight loop.
        await this.sleep(this.pollMs);
        return this.journal.get(record.operationId);
      }
      if (classified.code === 'APPROVAL_NOT_ACTIVE' && record.broadcast) {
        fail('RECOVERY_AUTHORIZATION_REQUIRED', {
          layer: 'signer', step, transactionHash: record.signed.ethereumTransactionHash,
          notAfter: this.notAfter, journalState: record.state, attempts: record.broadcast.attempts
        });
      }
      fail('SEND_REJECTED', { ...classified.details, layer: classified.details.layer ?? 'brickken-api', step, cause: classified.code });
    }
  }

  async #track(step, record) {
    const { primary, secondary } = this.rpcs;
    const hash = record.signed.ethereumTransactionHash;
    const receipt = (await primary.getTransactionReceipt(hash)) ?? (await secondary.getTransactionReceipt(hash));
    if (receipt) return this.#confirm(step, record, receipt);
    const [byPrimary, bySecondary, latestNonce] = await Promise.all([
      primary.getTransactionByHash(hash), secondary.getTransactionByHash(hash),
      primary.getTransactionCount(record.transaction.from, 'latest')
    ]);
    const seen = byPrimary ?? bySecondary;
    const next = this.journal.recoverUncertain(record.operationId, {
      observedAt: iso(this.now()),
      transactionByHash: seen ? { transactionHash: seen.hash, nonce: seen.nonce, from: seen.from } : null,
      latestNonce
    });
    if (next.broadcast.result === 'nonce-conflict') {
      fail('NONCE_CONFLICT', { layer: 'chain', step, nonce: record.transaction.nonce, transactionHash: hash });
    }
    if (!seen) {
      const waited = this.now() - Date.parse(next.broadcast.lastAttemptAt);
      const threshold = next.state === 'uncertain' ? RESEND_UNCERTAIN_AFTER_MS : RESEND_BROADCAST_AFTER_MS;
      if (waited >= threshold) {
        if (!this.#writesAllowed()) {
          // Tracking by reads continues in tracking-only mode; a resend after the
          // approval expired needs a recovery authorization for exactly this hash.
          if (this.trackingOnly) { await this.sleep(this.pollMs); return this.journal.get(record.operationId); }
          fail('RECOVERY_AUTHORIZATION_REQUIRED', {
            layer: 'local-validation', step, transactionHash: hash, notAfter: this.notAfter,
            journalState: next.state, attempts: next.broadcast.attempts
          });
        }
        if (broadcastBackoffUntil(next, this.now()) !== null) {
          // The window budget is used: observe by reads until the oldest attempt ages out.
          await this.sleep(this.pollMs);
          return this.journal.get(record.operationId);
        }
        if (typeof this.signer?.role === 'string' && this.signer.role !== plan.LIVE_STEP_SIGNER[step]) {
          // Bytes signed by the other role are resent only by that role's process; this one keeps tracking.
          await this.sleep(this.pollMs);
          return this.journal.get(record.operationId);
        }
        // Only the identical signed bytes may be sent again, through the same route.
        this.journal.authorizeIdenticalResend(record.operationId, next.signed.signedTransaction);
        return this.#broadcast(step, next);
      }
    }
    await this.sleep(this.pollMs);
    return this.journal.get(record.operationId);
  }

  async #confirm(step, record, receipt) {
    const { primary, secondary } = this.rpcs;
    const hash = record.signed.ethereumTransactionHash;
    if (receipt.transactionHash !== hash || receipt.from !== record.transaction.from || receipt.to !== record.transaction.to) {
      fail('RECEIPT_IDENTITY', { layer: 'rpc', step, transactionHash: hash });
    }
    // Depth is measured on both sources; the step waits for the shallower one.
    const [latestPrimary, latestSecondary] = await Promise.all([primary.blockNumber(), secondary.blockNumber()]);
    const depth = tip => Number(BigInt(tip) - BigInt(receipt.blockNumber) + 1n);
    const confirmationsPrimary = depth(latestPrimary);
    const confirmationsSecondary = depth(latestSecondary);
    const confirmations = Math.min(confirmationsPrimary, confirmationsSecondary);
    if (confirmations < this.proposal.confirmations.stepProgression) {
      await this.sleep(this.pollMs);
      return this.journal.get(record.operationId);
    }
    const [primaryBlock, secondaryBlock, secondaryReceipt] = await Promise.all([
      primary.getBlock({ blockNumber: receipt.blockNumber }),
      secondary.getBlock({ blockNumber: receipt.blockNumber }),
      secondary.getTransactionReceipt(hash)
    ]);
    if (!primaryBlock || primaryBlock.hash !== receipt.blockHash || !secondaryBlock || !secondaryReceipt) {
      // A reorganisation in progress or a lagging source: observe again later.
      await this.sleep(this.pollMs);
      return this.journal.get(record.operationId);
    }
    if (secondaryBlock.hash !== receipt.blockHash || secondaryReceipt.blockHash !== receipt.blockHash ||
        secondaryReceipt.status !== receipt.status) fail('SOURCE_DISAGREEMENT', { layer: 'rpc', step, transactionHash: hash });
    const next = this.journal.confirm(record.operationId, {
      transactionHash: hash, blockNumber: receipt.blockNumber, blockHash: receipt.blockHash,
      secondaryBlockHash: secondaryBlock.hash, receiptStatus: receipt.status, confirmations, checkedAt: iso(this.now())
    });
    this.onEvidence(`${record.operationId}-receipt`, {
      operationId: record.operationId, step, receipt, secondaryBlockHash: secondaryBlock.hash,
      confirmations, confirmationsPrimary, confirmationsSecondary
    });
    if (next.state === 'reverted') {
      const replay = await primary.call({ from: record.transaction.from, to: record.transaction.to, data: record.transaction.data }, { blockHash: primaryBlock.parentHash });
      fail('TRANSACTION_REVERTED', {
        layer: 'contract', step, transactionHash: hash,
        revert: replay.ok ? null : plan.decodeRevert(replay.revertData)
      });
    }
    return next;
  }

  async #verify(step, record) {
    const proposal = this.proposal;
    const { primary, secondary } = this.rpcs;
    const hash = record.signed.ethereumTransactionHash;
    const [receipt, mined, block] = await Promise.all([
      primary.getTransactionReceipt(hash), primary.getTransactionByHash(hash),
      primary.getBlock({ blockHash: record.confirmation.blockHash })
    ]);
    if (!receipt || !mined || !block || receipt.blockHash !== record.confirmation.blockHash || mined.blockHash !== receipt.blockHash) {
      // The recorded block is no longer what the source returns; recheck before any conclusion.
      await this.sleep(this.pollMs);
      await this.recheck([record.operationId]);
      return this.journal.get(record.operationId);
    }
    // The second source must return the same receipt block and the same parent
    // before either state is read from it.
    const [secondaryBlock, secondaryParent] = await Promise.all([
      secondary.getBlock({ blockHash: receipt.blockHash }), secondary.getBlock({ blockHash: block.parentHash })
    ]);
    if (!secondaryBlock || !secondaryParent || secondaryBlock.parentHash !== block.parentHash ||
        BigInt(secondaryParent.number) + 1n !== BigInt(block.number)) {
      await this.sleep(this.pollMs);
      await this.recheck([record.operationId]);
      return this.journal.get(record.operationId);
    }
    const beforeRef = { blockHash: block.parentHash };
    const afterRef = { blockHash: receipt.blockHash };
    const beforeState = await postcheckState(proposal, step, primary, beforeRef);
    const beforeSecondary = await postcheckState(proposal, step, secondary, beforeRef);
    if (canonicalJson(beforeState) !== canonicalJson(beforeSecondary)) fail('SOURCE_STATE_DISAGREEMENT', { layer: 'rpc', step, field: 'before' });
    const afterState = await postcheckState(proposal, step, primary, afterRef);
    const afterSecondary = await postcheckState(proposal, step, secondary, afterRef);
    if (canonicalJson(afterState) !== canonicalJson(afterSecondary)) fail('SOURCE_STATE_DISAGREEMENT', { layer: 'rpc', step, field: 'after' });
    const twoSourceObservation = {
      parentBlock: { number: secondaryParent.number, hash: block.parentHash },
      receiptBlock: { number: block.number, hash: receipt.blockHash },
      before: { primary: beforeState, secondary: beforeSecondary, agreed: true },
      after: { primary: afterState, secondary: afterSecondary, agreed: true }
    };
    const trusted = {
      transaction: { hash, ...record.transaction },
      semantics: semanticsFor(proposal, step, record)
    };
    const envelope = {
      schemaVersion: 1,
      operationKind: livePostcheckKind(step),
      expected: structuredClone(trusted),
      transaction: { ...mined },
      receipt: toPostcheckReceipt(receipt),
      before: { blockNumber: (BigInt(receipt.blockNumber) - 1n).toString(), blockHash: block.parentHash, state: beforeState },
      after: { blockNumber: receipt.blockNumber, blockHash: receipt.blockHash, state: afterState },
      observedAt: iso(this.now())
    };
    const observation = this.cleanup && step === 'revoke' ? LIVE_CLEANUP_REVOCATION : LIVE_OBSERVATION;
    let report;
    try { report = VERIFIERS[livePostcheckKind(step)](envelope, trusted, observation); }
    catch (error) { fail('SEMANTIC_CHECK_FAILED', { layer: 'contract', step, check: error?.code ?? null, transactionHash: hash }); }
    const next = this.journal.markSemanticallyVerified(record.operationId, report);
    this.onEvidence(`${record.operationId}-postcheck`, { operationId: record.operationId, step, envelope, report, twoSourceObservation });
    return next;
  }
}

// A block-bound observation is aggregated per source. It is canonical (true)
// only while both sources return the recorded hash at the recorded height. It
// is not canonical (false) as soon as any source that returned a block returned
// a different hash: one source has then proved the block left the chain, and a
// missing answer from the other cannot hide that (A1-F06). It is unresolved
// (null) only when no source disagrees but both did not confirm, because one
// or both have no block at that height yet; a caller may wait on null, never
// build on it. Used for the read-only controls.
export async function checkControlCanonicity({ rpcs, controls }) {
  const { primary, secondary } = rpcs;
  const results = [];
  for (const control of controls) {
    const [a, b] = await Promise.all([
      primary.getBlock({ blockNumber: control.blockNumber }), secondary.getBlock({ blockNumber: control.blockNumber })
    ]);
    const primaryMatch = a ? a.hash === control.blockHash : null;
    const secondaryMatch = b ? b.hash === control.blockHash : null;
    results.push({
      controlId: control.controlId, blockNumber: control.blockNumber, blockHash: control.blockHash,
      primaryHash: a?.hash ?? null, secondaryHash: b?.hash ?? null, primaryMatch, secondaryMatch,
      canonical: primaryMatch === false || secondaryMatch === false ? false
        : primaryMatch === true && secondaryMatch === true ? true : null
    });
  }
  return results;
}

// Every successful write block and every control block must be finalized on
// both sources with the recorded hash before the run is reported as final.
export async function checkRunFinality({ rpcs, journal, operationIds, controls = [] }) {
  const { primary, secondary } = rpcs;
  const [finalA, finalB] = await Promise.all([primary.getBlock('finalized'), secondary.getBlock('finalized')]);
  const entries = [];
  const finalizedAt = async (blockNumber, blockHash) => {
    const [a, b] = await Promise.all([primary.getBlock({ blockNumber }), secondary.getBlock({ blockNumber })]);
    return Boolean(finalA && finalB && a && b) &&
      BigInt(finalA.number) >= BigInt(blockNumber) && BigInt(finalB.number) >= BigInt(blockNumber) &&
      a.hash === blockHash && b.hash === blockHash;
  };
  for (const operationId of operationIds) {
    const record = journal.find(operationId);
    if (!record || record.state !== 'semantically_verified') {
      entries.push({ operationId, finalized: false, reason: 'NOT_VERIFIED' });
      continue;
    }
    entries.push({
      operationId, blockNumber: record.confirmation.blockNumber, blockHash: record.confirmation.blockHash,
      finalized: await finalizedAt(record.confirmation.blockNumber, record.confirmation.blockHash)
    });
  }
  for (const control of controls) {
    if (!control.observed || control.passed !== true || control.canonical === false) {
      entries.push({ controlId: control.controlId, finalized: false, reason: control.observed ? (control.canonical === false ? 'NOT_CANONICAL' : 'NOT_PASSED') : 'NOT_OBSERVED' });
      continue;
    }
    entries.push({
      controlId: control.controlId, blockNumber: control.blockNumber, blockHash: control.blockHash,
      finalized: await finalizedAt(control.blockNumber, control.blockHash)
    });
  }
  return Object.freeze({
    primaryFinalized: finalA ? { number: finalA.number, hash: finalA.hash } : null,
    secondaryFinalized: finalB ? { number: finalB.number, hash: finalB.hash } : null,
    entries,
    allFinalized: entries.some(entry => entry.operationId) && entries.every(entry => entry.finalized)
  });
}
