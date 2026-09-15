// Live Sepolia run plan. It turns the reviewed live proposal into exact
// per-step expectations: Brickken facade request bodies, complete calldata
// built with the existing encoders, read-only control calls and the run
// approval document that the owner approves and the signer loads. It has no
// HTTP, wallet, signing or broadcast capability; it only reads the proposal.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  KNOWN_AGENT,
  KNOWN_PRINCIPAL,
  SEPOLIA_CHAIN_ID,
  TRANSFER_FROM_ACTION,
  TRANSFER_FROM_SELECTOR,
  canonicalJson,
  createTransferFromIntent,
  sha256Canonical
} from './brickken-intent.mjs';
import {
  EXECUTE_SELECTOR,
  PROVISIONED_EXECUTOR,
  buildOfflineExecutionCall,
  encodeSetActionTransferFrom
} from './brickken-executor.mjs';
import { RAMS_REGISTRY, buildDirectMandatePlan, buildDirectRevokePlan } from './brickken-mandate.mjs';
import {
  DIRECT_LIFECYCLE_DEADLINE,
  EMPTY_METADATA,
  EMPTY_SIGNATURE,
  GRANT_MANDATE_SELECTOR,
  encodeDirectGrantMandateCalldata,
  encodeDirectRevokeMandateCalldata
} from './brickken-lifecycle.mjs';
import { SANDBOX_IDENTITY_REF } from './brickken-prepare.mjs';
import { APPROVE_SELECTOR, encodeApproveExecutor } from './brickken-envelope.mjs';
import { BRICKKEN_RAMS_PREPARE_PATHS, BRICKKEN_SANDBOX_ORIGIN } from './brickken-http.mjs';

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const LIVE_PROPOSAL_FILE = path.join(PROJECT_ROOT, 'integration', 'live-proposal.json');
export const LIVE_PROPOSAL_HASH = '415254ccd0c7d2764e5175743cc4dec6f718bf51bf0d556fda52bee8c03f6533';
export const LIVE_COMPLIANCE_PROVIDER = '0xa90d2503d5d9b80ecc27856ff76f892b8c02f278';
export const LIVE_TOKEN = '0x1c7d4b196cb0c7b01d743fbc6116a902379c7238';
export const LIVE_READ_ENDPOINTS = Object.freeze({
  primary: 'https://ethereum-sepolia-rpc.publicnode.com',
  secondary: 'https://sepolia.rpc.thirdweb.com'
});
export const LIVE_WRITE_STEPS = Object.freeze(['setAction', 'approve', 'grant', 'execute', 'revoke', 'approveReset']);
export const LIVE_STEP_SIGNER = Object.freeze({
  setAction: 'owner', approve: 'owner', grant: 'owner', execute: 'agent', revoke: 'owner', approveReset: 'owner'
});
export const LIVE_STEP_ROUTE = Object.freeze({
  setAction: 'brickken-api', approve: 'sepolia-rpc', grant: 'brickken-api',
  execute: 'brickken-api', revoke: 'brickken-api', approveReset: 'sepolia-rpc'
});
// A step may be signed only after these steps were signed under the same approval.
export const LIVE_STEP_PREREQUISITES = Object.freeze({
  setAction: Object.freeze([]), approve: Object.freeze([]), grant: Object.freeze(['approve']),
  execute: Object.freeze(['grant']), revoke: Object.freeze(['grant']), approveReset: Object.freeze(['approve'])
});
export const LIVE_CONTROL_IDS = Object.freeze([
  'control-transaction-cap', 'control-cumulative-cap', 'control-before-revoke', 'control-after-revoke'
]);
export const GRANT_START_TOLERANCE_SECONDS = 300;
export const MAX_APPROVAL_LIFETIME_SECONDS = 4 * 24 * 3600;
export const READ_SELECTORS = Object.freeze({
  canExecute: '0xf80ba00f', getMandate: '0xc5e98345', isActionEnabled: '0x0c53b010', isFrozen: '0xe5839836',
  balanceOf: '0x70a08231', allowance: '0xdd62ed3e', actions: '0x7b37e5f4', decimals: '0x313ce567',
  owner: '0x8da5cb5b', rams: '0xd47cf1ac', principal: '0xba5d3078', hasRole: '0x91d14854'
});
export const RECORDER_ROLE = '0xf996da754c790e95d5c7ca3330cfcad529487fe9d1d8edb7afc65076fdf9adb4';
// Custom error selectors from the source-verified AgentMandate and AgentExecutor ABIs.
export const CUSTOM_ERRORS = Object.freeze({
  '0x0aae0b09': 'CannotExecute', '0xfc316461': 'NoActiveMandate', '0x47ee14ea': 'NotExecutable',
  '0x6480f20c': 'ExceedsTransactionCap', '0x30c377a8': 'ExceedsCumulativeCap', '0x8c91850f': 'UnsupportedAction',
  '0x8d64f6c5': 'PrincipalNotEligible', '0x8f2d3ce4': 'MandateAlreadyActive', '0xd36c8500': 'InvalidExpiry',
  '0x789a70b0': 'NotPrincipal', '0xea8e4eb5': 'NotAuthorized', '0x118cdaa7': 'OwnableUnauthorizedAccount',
  '0xa5fa8d2b': 'CallFailed', '0x08c379a0': 'Error'
});

const UINT256_MAX = (1n << 256n) - 1n;
const MAX_PROPOSAL_BYTES = 65_536;
const TX_KEYS = ['chainId', 'from', 'to', 'value', 'data', 'nonce', 'gasLimit', 'type', 'maxPriorityFeePerGas', 'maxFeePerGas'];
const REVOKE_REFERENCE_TIME = 1_789_000_000;
const MIN_GAS_LIMIT = 21_000n;

export class BrickkenLivePlanError extends Error {
  constructor(code) { super(code); this.name = 'BrickkenLivePlanError'; this.code = code; }
}
function fail(code) { throw new BrickkenLivePlanError(code); }
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value));
}
function shape(value, keys, code = 'STRUCTURE') {
  if (!plain(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(code);
}
function uint(value, code = 'INTEGER') {
  if (typeof value !== 'string' || value.length > 78 || !/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value) > UINT256_MAX) fail(code);
  return value;
}
function second(value, code = 'TIME') {
  if (!Number.isSafeInteger(value) || value <= 0) fail(code);
  return value;
}
function address(value, code = 'ADDRESS') {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{40}$/.test(value) || /^0x0{40}$/.test(value)) fail(code);
  return value;
}
function hex(value, code = 'HEX') {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-f]{2})*$/.test(value)) fail(code);
  return value;
}
function word(value) { return BigInt(value).toString(16).padStart(64, '0'); }
function addressWord(value) { return '0'.repeat(24) + address(value).slice(2); }
function iso(value) {
  if (typeof value !== 'string' || new Date(value).toISOString() !== value) fail('TIME');
  return value;
}

// ---------------------------------------------------------------------------
// Proposal

export function validateLiveProposal(value) {
  if (!plain(value) || typeof value.proposalHash !== 'string') fail('PROPOSAL_INVALID');
  const { proposalHash, ...payload } = value;
  if (proposalHash !== LIVE_PROPOSAL_HASH || sha256Canonical(payload) !== proposalHash) fail('PROPOSAL_HASH');
  // The hash pins the reviewed bytes; these checks keep the code's own
  // constants and the proposal from drifting apart silently.
  if (value.kind !== 'live-sepolia-proposal' || value.chainId !== SEPOLIA_CHAIN_ID ||
      value.principal !== KNOWN_PRINCIPAL || value.agent !== KNOWN_AGENT ||
      value.executor !== PROVISIONED_EXECUTOR || value.registry !== RAMS_REGISTRY ||
      value.complianceProvider !== LIVE_COMPLIANCE_PROVIDER || value.identityRef !== SANDBOX_IDENTITY_REF ||
      value.token?.address !== LIVE_TOKEN || value.token?.decimals !== 6) fail('PROPOSAL_BINDING');
  const recipient = address(value.recipient?.address, 'PROPOSAL_BINDING');
  if ([KNOWN_PRINCIPAL, KNOWN_AGENT, PROVISIONED_EXECUTOR, RAMS_REGISTRY, LIVE_TOKEN].includes(recipient)) fail('PROPOSAL_BINDING');
  const limits = value.limits;
  const amounts = value.amounts;
  const maxTx = BigInt(uint(limits?.maxTransactionValue));
  const maxCum = BigInt(uint(limits?.maxCumulativeValue));
  const allowance = BigInt(uint(limits?.allowance));
  const execute = BigInt(uint(amounts?.execute));
  const over = BigInt(uint(amounts?.overTransactionCapProbe));
  const cumAllowed = BigInt(uint(amounts?.cumulativeAllowedProbe));
  const cumDenied = BigInt(uint(amounts?.cumulativeDeniedProbe));
  const revocation = BigInt(uint(amounts?.revocationProbe));
  if (!(execute > 0n && execute <= maxTx && over > maxTx && over <= allowance &&
        allowance === maxCum && execute < maxCum && cumAllowed === maxCum - execute &&
        cumDenied > cumAllowed && cumDenied <= maxTx &&
        revocation > 0n && revocation <= cumAllowed &&
        BigInt(uint(limits.minimumPrincipalTokenBalance)) >= execute + cumAllowed)) fail('PROPOSAL_AMOUNTS');
  if (!Number.isSafeInteger(value.mandateValiditySeconds) || value.mandateValiditySeconds < 600 ||
      value.mandateValiditySeconds > 3600) fail('PROPOSAL_VALIDITY');
  const routes = value.routes;
  if (routes?.brickkenApi?.origin !== BRICKKEN_SANDBOX_ORIGIN || routes.brickkenApi.paymentFallback !== false ||
      canonicalJson(routes.brickkenApi.prepare) !== canonicalJson(BRICKKEN_RAMS_PREPARE_PATHS) ||
      routes.readEndpoints?.primary !== LIVE_READ_ENDPOINTS.primary ||
      routes.readEndpoints?.secondary !== LIVE_READ_ENDPOINTS.secondary ||
      routes.sepoliaRpc?.broadcastEndpoint !== LIVE_READ_ENDPOINTS.primary ||
      canonicalJson(routes.sepoliaRpc?.operations) !== canonicalJson(['approve', 'approveReset'])) fail('PROPOSAL_ROUTES');
  const maxFee = BigInt(uint(value.fees?.maxFeePerGas));
  const maxPriority = BigInt(uint(value.fees?.maxPriorityFeePerGas));
  if (maxFee === 0n || maxPriority > maxFee) fail('PROPOSAL_FEES');
  shape(value.gasLimitCaps, LIVE_WRITE_STEPS, 'PROPOSAL_GAS');
  for (const step of LIVE_WRITE_STEPS) {
    if (BigInt(uint(value.gasLimitCaps[step])) < MIN_GAS_LIMIT || BigInt(value.gasLimitCaps[step]) > 1_000_000n) fail('PROPOSAL_GAS');
  }
  if (!Number.isSafeInteger(value.confirmations?.stepProgression) || value.confirmations.stepProgression < 1 ||
      canonicalJson(value.writes) !== canonicalJson(LIVE_WRITE_STEPS)) fail('PROPOSAL_SEQUENCE');
  return value;
}

export function loadLiveProposal(file = LIVE_PROPOSAL_FILE) {
  let parsed;
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > MAX_PROPOSAL_BYTES) fail('PROPOSAL_UNAVAILABLE');
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    if (error instanceof BrickkenLivePlanError) throw error;
    fail('PROPOSAL_UNAVAILABLE');
  }
  return validateLiveProposal(parsed);
}

// ---------------------------------------------------------------------------
// Exact calldata

function transferPolicy(proposal, cumulativeUsed, allowance) {
  return {
    chainId: SEPOLIA_CHAIN_ID,
    principal: proposal.principal,
    agent: proposal.agent,
    executor: proposal.executor,
    token: proposal.token.address,
    recipient: proposal.recipient.address,
    action: { selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: true, amountIndex: 2 },
    maxTransactionValue: proposal.limits.maxTransactionValue,
    maxCumulativeValue: proposal.limits.maxCumulativeValue,
    cumulativeUsed,
    allowance
  };
}

// The approved agent transfer, validated by the existing intent rules.
export function liveExecutionCall(proposal) {
  const intent = createTransferFromIntent(
    transferPolicy(proposal, '0', proposal.limits.allowance),
    { from: proposal.principal, to: proposal.recipient.address, amount: proposal.amounts.execute }
  );
  return buildOfflineExecutionCall(intent);
}

// Read-only probe calldata. It is deliberately not validated against the
// intent caps, because the over-cap probe must be expressible. The signer
// never accepts it: it signs only the exact approved execute calldata.
export function encodeExecuteProbe(proposal, amount) {
  const inner = TRANSFER_FROM_SELECTOR + addressWord(proposal.principal) +
    addressWord(proposal.recipient.address) + word(uint(amount));
  return EXECUTE_SELECTOR + addressWord(proposal.token.address) + word(64) + word(100) +
    inner.slice(2) + '0'.repeat(56);
}

function mandatePlanAt(proposal, call, validFrom) {
  return buildDirectMandatePlan(call, { validFrom, validUntil: validFrom + proposal.mandateValiditySeconds }, validFrom);
}

export function expectedGrantCalldata(proposal, validFromInput) {
  const validFrom = second(validFromInput, 'GRANT_WINDOW');
  const call = liveExecutionCall(proposal);
  const plan = mandatePlanAt(proposal, call, validFrom);
  const body = plan.request.body;
  const reference = {
    schemaVersion: 1,
    kind: 'rams-direct-grant-reference',
    mandatePlanHash: plan.planHash,
    executionCallHash: call.callHash,
    registry: RAMS_REGISTRY,
    caller: KNOWN_PRINCIPAL,
    agent: KNOWN_AGENT,
    principal: KNOWN_PRINCIPAL,
    complianceProvider: LIVE_COMPLIANCE_PROVIDER,
    identityRef: body.identityRef,
    asset: call.intent.policy.token,
    maxTransactionValue: call.intent.policy.maxTransactionValue,
    maxCumulativeValue: call.intent.policy.maxCumulativeValue,
    validFrom: body.validFrom,
    validUntil: body.validUntil,
    metadata: EMPTY_METADATA,
    actions: [TRANSFER_FROM_ACTION],
    deadline: DIRECT_LIFECYCLE_DEADLINE,
    signature: EMPTY_SIGNATURE
  };
  return encodeDirectGrantMandateCalldata(plan, call, validFrom, reference);
}

// Returns the validFrom word of grantMandate calldata so the full calldata can
// be rebuilt and compared; the value itself proves nothing.
export function grantValidFrom(data) {
  hex(data, 'CALLDATA');
  if (data.length !== 2 + 548 * 2 || data.slice(0, 10) !== GRANT_MANDATE_SELECTOR) fail('CALLDATA');
  const value = BigInt('0x' + data.slice(10 + 3 * 64, 10 + 4 * 64));
  if (value <= 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) fail('CALLDATA');
  return Number(value);
}

export function expectedRevokeCalldata(proposal) {
  const call = liveExecutionCall(proposal);
  const plan = mandatePlanAt(proposal, call, REVOKE_REFERENCE_TIME);
  const revokePlan = buildDirectRevokePlan();
  const reference = {
    schemaVersion: 1,
    kind: 'rams-direct-revoke-reference',
    revokePlanHash: revokePlan.planHash,
    mandatePlanHash: plan.planHash,
    registry: RAMS_REGISTRY,
    caller: KNOWN_PRINCIPAL,
    agent: KNOWN_AGENT,
    principal: KNOWN_PRINCIPAL,
    deadline: DIRECT_LIFECYCLE_DEADLINE,
    signature: EMPTY_SIGNATURE
  };
  return encodeDirectRevokeMandateCalldata(revokePlan, plan, call, REVOKE_REFERENCE_TIME, reference);
}

export function expectedCalldata(proposal, step, { validFrom = null } = {}) {
  switch (step) {
    case 'setAction': return encodeSetActionTransferFrom();
    case 'approve': return encodeApproveExecutor(proposal.limits.allowance);
    case 'grant': return expectedGrantCalldata(proposal, validFrom);
    case 'execute': return liveExecutionCall(proposal).call.data;
    case 'revoke': return expectedRevokeCalldata(proposal);
    case 'approveReset': return APPROVE_SELECTOR + addressWord(proposal.executor) + word(0);
    default: return fail('STEP');
  }
}

export function stepTarget(proposal, step) {
  if (step === 'setAction' || step === 'execute') return proposal.executor;
  if (step === 'approve' || step === 'approveReset') return proposal.token.address;
  if (step === 'grant' || step === 'revoke') return proposal.registry;
  return fail('STEP');
}

export function stepSignerAddress(proposal, step) {
  if (!LIVE_WRITE_STEPS.includes(step)) fail('STEP');
  return LIVE_STEP_SIGNER[step] === 'agent' ? proposal.agent : proposal.principal;
}

// ---------------------------------------------------------------------------
// Brickken facade bodies

function nonceNumber(value) {
  const nonce = uint(value, 'NONCE');
  if (BigInt(nonce) > BigInt(Number.MAX_SAFE_INTEGER)) fail('NONCE');
  return Number(nonce);
}

export function facadeBody(proposal, step, { nonce, gasLimit, validFrom = null }) {
  if (LIVE_STEP_ROUTE[step] !== 'brickken-api') fail('ROUTE');
  const cap = BigInt(proposal.gasLimitCaps[step]);
  const limit = uint(gasLimit, 'GAS_LIMIT');
  if (BigInt(limit) < MIN_GAS_LIMIT || BigInt(limit) > cap) fail('GAS_LIMIT');
  const common = { chainId: SEPOLIA_CHAIN_ID, nonce: nonceNumber(nonce), gasLimit: limit };
  switch (step) {
    case 'setAction':
      return {
        ...common, signerAddress: proposal.principal, executorAddress: proposal.executor,
        selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: true, amountIndex: 2
      };
    case 'grant': {
      const start = second(validFrom, 'GRANT_WINDOW');
      return {
        ...common, signerAddress: proposal.principal, agent: proposal.agent, principal: proposal.principal,
        validFrom: start, validUntil: start + proposal.mandateValiditySeconds,
        complianceProvider: proposal.complianceProvider, identityRef: proposal.identityRef,
        asset: proposal.token.address, maxTransactionValue: proposal.limits.maxTransactionValue,
        maxCumulativeValue: proposal.limits.maxCumulativeValue, metadata: EMPTY_METADATA,
        actions: [TRANSFER_FROM_SELECTOR], agentMandateAddress: proposal.registry
      };
    }
    case 'execute':
      return {
        ...common, signerAddress: proposal.agent, executorAddress: proposal.executor,
        target: proposal.token.address, data: liveExecutionCall(proposal).intent.innerCalldata
      };
    case 'revoke':
      return {
        ...common, signerAddress: proposal.principal, agent: proposal.agent, principal: proposal.principal,
        agentMandateAddress: proposal.registry
      };
    default:
      return fail('STEP');
  }
}

// The signer uses this to accept a prepare body only when it is exactly the
// body this plan would build for the same nonce, gas limit and grant start.
export function validateFacadeBody(proposal, step, body, nowSeconds) {
  if (!plain(body)) fail('BODY');
  const now = second(nowSeconds);
  const options = { nonce: typeof body.nonce === 'number' && Number.isSafeInteger(body.nonce) && body.nonce >= 0 ? String(body.nonce) : fail('NONCE'), gasLimit: body.gasLimit };
  if (step === 'grant') {
    options.validFrom = body.validFrom;
    if (Math.abs(second(body.validFrom, 'GRANT_WINDOW') - now) > GRANT_START_TOLERANCE_SECONDS) fail('GRANT_WINDOW');
  }
  const rebuilt = facadeBody(proposal, step, options);
  if (canonicalJson(body) !== canonicalJson(rebuilt)) fail('BODY_MISMATCH');
  return rebuilt;
}

// ---------------------------------------------------------------------------
// Transactions

export function normalizeLiveTransaction(value) {
  shape(value, TX_KEYS, 'TRANSACTION');
  if (value.type !== 2) fail('TRANSACTION_TYPE');
  const result = {
    chainId: uint(value.chainId), from: address(value.from), to: address(value.to), value: uint(value.value),
    data: hex(value.data), nonce: uint(value.nonce), gasLimit: uint(value.gasLimit), type: 2,
    maxPriorityFeePerGas: uint(value.maxPriorityFeePerGas), maxFeePerGas: uint(value.maxFeePerGas)
  };
  if (BigInt(result.maxPriorityFeePerGas) > BigInt(result.maxFeePerGas)) fail('TRANSACTION_FEES');
  return Object.freeze(result);
}

// Complete pre-signature check shared by the adapter and the signer: chain,
// signer, target, zero native value, independently rebuilt calldata, optional
// exact nonce, and the approved gas and fee ceilings.
export function checkLiveTransaction(proposal, step, transactionInput, { nonce = null } = {}) {
  if (!LIVE_WRITE_STEPS.includes(step)) fail('STEP');
  const tx = normalizeLiveTransaction(transactionInput);
  if (tx.chainId !== SEPOLIA_CHAIN_ID) fail('WRONG_CHAIN');
  if (tx.from !== stepSignerAddress(proposal, step)) fail('WRONG_SIGNER');
  if (tx.to !== stepTarget(proposal, step)) fail('WRONG_TARGET');
  if (tx.value !== '0') fail('NATIVE_VALUE');
  const expected = expectedCalldata(proposal, step, step === 'grant' ? { validFrom: grantValidFrom(tx.data) } : {});
  if (tx.data !== expected) fail('CALLDATA_MISMATCH');
  if (nonce !== null && tx.nonce !== uint(nonce, 'NONCE')) fail('NONCE_MISMATCH');
  if (BigInt(tx.gasLimit) < MIN_GAS_LIMIT || BigInt(tx.gasLimit) > BigInt(proposal.gasLimitCaps[step])) fail('GAS_LIMIT_CEILING');
  if (BigInt(tx.maxFeePerGas) > BigInt(proposal.fees.maxFeePerGas)) fail('FEE_CEILING');
  if (BigInt(tx.maxPriorityFeePerGas) > BigInt(proposal.fees.maxPriorityFeePerGas)) fail('PRIORITY_FEE_CEILING');
  return tx;
}

export function maxStepCostWei(proposal, step) {
  return (BigInt(proposal.gasLimitCaps[step]) * BigInt(proposal.fees.maxFeePerGas)).toString();
}

export function requiredWei(proposal, steps) {
  const totals = { owner: 0n, agent: 0n };
  for (const step of steps) {
    if (!LIVE_WRITE_STEPS.includes(step)) fail('STEP');
    totals[LIVE_STEP_SIGNER[step]] += BigInt(maxStepCostWei(proposal, step));
  }
  return { owner: totals.owner.toString(), agent: totals.agent.toString() };
}

// ---------------------------------------------------------------------------
// Read-only calls and their decoding

function readCall(to, data) { return Object.freeze({ to, data }); }

export function readCalls(proposal) {
  const action = TRANSFER_FROM_ACTION.slice(2);
  return Object.freeze({
    canExecute: amount => readCall(proposal.registry, READ_SELECTORS.canExecute + addressWord(proposal.agent) +
      addressWord(proposal.principal) + addressWord(proposal.token.address) + action + word(uint(amount))),
    getMandate: () => readCall(proposal.registry, READ_SELECTORS.getMandate + addressWord(proposal.agent) + addressWord(proposal.principal)),
    isActionEnabled: () => readCall(proposal.registry, READ_SELECTORS.isActionEnabled + addressWord(proposal.agent) +
      addressWord(proposal.principal) + action),
    isFrozen: () => readCall(proposal.registry, READ_SELECTORS.isFrozen + addressWord(proposal.agent)),
    hasRecorderRole: () => readCall(proposal.registry, READ_SELECTORS.hasRole + RECORDER_ROLE.slice(2) + addressWord(proposal.executor)),
    balanceOf: holder => readCall(proposal.token.address, READ_SELECTORS.balanceOf + addressWord(holder)),
    allowance: () => readCall(proposal.token.address, READ_SELECTORS.allowance + addressWord(proposal.principal) + addressWord(proposal.executor)),
    decimals: () => readCall(proposal.token.address, READ_SELECTORS.decimals),
    executorAction: () => readCall(proposal.executor, READ_SELECTORS.actions + TRANSFER_FROM_SELECTOR.slice(2) + '0'.repeat(56)),
    executorRams: () => readCall(proposal.executor, READ_SELECTORS.rams),
    executorPrincipal: () => readCall(proposal.executor, READ_SELECTORS.principal),
    executorOwner: () => readCall(proposal.executor, READ_SELECTORS.owner)
  });
}

function words(data, count) {
  hex(data, 'RETURN_DATA');
  if (data.length !== 2 + count * 64) fail('RETURN_DATA');
  return Array.from({ length: count }, (_, index) => data.slice(2 + index * 64, 2 + (index + 1) * 64));
}
export function decodeUintReturn(data) { return BigInt('0x' + words(data, 1)[0]).toString(); }
export function decodeBoolReturn(data) {
  const value = BigInt('0x' + words(data, 1)[0]);
  if (value > 1n) fail('RETURN_DATA');
  return value === 1n;
}
export function decodeAddressReturn(data) {
  const value = words(data, 1)[0];
  if (!value.startsWith('0'.repeat(24))) fail('RETURN_DATA');
  return '0x' + value.slice(24);
}
export function decodeActionSpecReturn(data) {
  const [supported, hasAmount, amountIndex] = words(data, 3).map(item => BigInt('0x' + item));
  if (supported > 1n || hasAmount > 1n || amountIndex > 255n) fail('RETURN_DATA');
  return Object.freeze({ supported: supported === 1n, hasAmount: hasAmount === 1n, amountIndex: Number(amountIndex) });
}
// getMandate returns a static tuple; a zero agent means no mandate is stored.
export function decodeMandateReturn(data) {
  const w = words(data, 12);
  const addr = item => {
    if (!item.startsWith('0'.repeat(24))) fail('RETURN_DATA');
    return '0x' + item.slice(24);
  };
  const flag = BigInt('0x' + w[4]);
  if (flag > 1n) fail('RETURN_DATA');
  const mandate = {
    agent: addr(w[0]), validFrom: BigInt('0x' + w[1]).toString(), validUntil: BigInt('0x' + w[2]).toString(),
    principal: addr(w[3]), revoked: flag === 1n, complianceProvider: addr(w[5]), identityRef: '0x' + w[6],
    asset: addr(w[7]), maxTransactionValue: BigInt('0x' + w[8]).toString(),
    maxCumulativeValue: BigInt('0x' + w[9]).toString(), cumulativeUsed: BigInt('0x' + w[10]).toString(),
    metadata: '0x' + w[11]
  };
  return mandate.agent === '0x' + '0'.repeat(40) ? null : Object.freeze(mandate);
}

// Names a revert from its selector. Arguments are decoded only for the two
// errors whose layout the checks rely on; anything else keeps its selector.
export function decodeRevert(revertData) {
  if (revertData === null) return Object.freeze({ selector: null, name: null, args: null });
  hex(revertData, 'REVERT_DATA');
  if (revertData.length < 10) return Object.freeze({ selector: null, name: null, args: null });
  const selector = revertData.slice(0, 10);
  const name = CUSTOM_ERRORS[selector] ?? null;
  let args = null;
  if (name === 'CannotExecute' && revertData.length === 10 + 4 * 64) {
    const w = words('0x' + revertData.slice(10), 4);
    args = {
      agent: '0x' + w[0].slice(24), target: '0x' + w[1].slice(24),
      selector: '0x' + w[2].slice(0, 8), amount: BigInt('0x' + w[3]).toString()
    };
  } else if (name === 'OwnableUnauthorizedAccount' && revertData.length === 10 + 64) {
    args = { account: '0x' + revertData.slice(10 + 24) };
  }
  return Object.freeze({ selector, name, args: args && Object.freeze(args) });
}

// Exact read-only control calls. None of them is ever a transaction.
export function controlCalls(proposal, controlId) {
  const calls = readCalls(proposal);
  const probe = amount => Object.freeze({
    from: proposal.agent, to: proposal.executor, value: '0', data: encodeExecuteProbe(proposal, amount)
  });
  const view = call => Object.freeze({ from: null, to: call.to, value: '0', data: call.data });
  switch (controlId) {
    case 'control-transaction-cap':
      return Object.freeze([
        Object.freeze({ label: 'execute-within-transaction-cap', ...probe(proposal.amounts.execute), expect: 'success' }),
        Object.freeze({ label: 'execute-over-transaction-cap', ...probe(proposal.amounts.overTransactionCapProbe), expect: 'revert:CannotExecute' })
      ]);
    case 'control-cumulative-cap':
      return Object.freeze([
        Object.freeze({ label: 'can-execute-remaining-cumulative', ...view(calls.canExecute(proposal.amounts.cumulativeAllowedProbe)), expect: 'true' }),
        Object.freeze({ label: 'can-execute-over-cumulative', ...view(calls.canExecute(proposal.amounts.cumulativeDeniedProbe)), expect: 'false' })
      ]);
    case 'control-before-revoke':
      return Object.freeze([
        Object.freeze({ label: 'execute-before-revoke', ...probe(proposal.amounts.revocationProbe), expect: 'success' })
      ]);
    case 'control-after-revoke':
      return Object.freeze([
        Object.freeze({ label: 'execute-after-revoke', ...probe(proposal.amounts.revocationProbe), expect: 'revert:CannotExecute' }),
        Object.freeze({ label: 'can-execute-after-revoke', ...view(calls.canExecute(proposal.amounts.revocationProbe)), expect: 'false' })
      ]);
    default:
      return fail('CONTROL');
  }
}

// ---------------------------------------------------------------------------
// Run approval

const APPROVAL_KEYS = [
  'schemaVersion', 'kind', 'proposalHash', 'network', 'chainId', 'createdAt', 'notAfter', 'signers',
  'contracts', 'identityRef', 'recipient', 'limits', 'amounts', 'mandateValiditySeconds', 'routes', 'fees',
  'budgetWei', 'writes', 'controls', 'noncePolicy', 'confirmationPolicy', 'cleanup', 'persistentConfiguration',
  'preflight', 'approvalSha256'
];

function writeEntries(proposal) {
  return LIVE_WRITE_STEPS.map(step => ({
    step,
    signer: LIVE_STEP_SIGNER[step],
    signerAddress: stepSignerAddress(proposal, step),
    route: LIVE_STEP_ROUTE[step],
    endpoint: LIVE_STEP_ROUTE[step] === 'brickken-api'
      ? BRICKKEN_SANDBOX_ORIGIN + BRICKKEN_RAMS_PREPARE_PATHS[step]
      : proposal.routes.sepoliaRpc.broadcastEndpoint,
    target: stepTarget(proposal, step),
    nativeValue: '0',
    calldata: step === 'grant' ? null : expectedCalldata(proposal, step),
    calldataRule: step === 'grant'
      ? `grantMandate for the fixed mandate, with validFrom set at preparation within ${GRANT_START_TOLERANCE_SECONDS} seconds of signing and validUntil = validFrom + ${proposal.mandateValiditySeconds}`
      : 'exact',
    maxGasLimit: proposal.gasLimitCaps[step],
    maxCostWei: maxStepCostWei(proposal, step),
    prerequisites: [...LIVE_STEP_PREREQUISITES[step]]
  }));
}

function controlEntries(proposal) {
  return LIVE_CONTROL_IDS.map(id => ({
    id,
    calls: controlCalls(proposal, id).map(item => ({ ...item })),
    broadcast: false
  }));
}

// preflight is the fresh observation the plan was built from. It is recorded
// for review; the run re-reads the chain before every write regardless.
export function buildRunApproval(proposalInput, { createdAt, notAfter, preflight }) {
  const proposal = validateLiveProposal(proposalInput);
  iso(createdAt); iso(notAfter);
  const lifetime = (Date.parse(notAfter) - Date.parse(createdAt)) / 1000;
  if (!(lifetime > 0 && lifetime <= MAX_APPROVAL_LIFETIME_SECONDS)) fail('APPROVAL_LIFETIME');
  if (preflight !== null && !plain(preflight)) fail('PREFLIGHT');
  const payload = {
    schemaVersion: 1,
    kind: 'mandate-desk-live-run-approval',
    proposalHash: proposal.proposalHash,
    network: proposal.network,
    chainId: proposal.chainId,
    createdAt,
    notAfter,
    signers: { owner: proposal.principal, agent: proposal.agent },
    contracts: {
      executor: proposal.executor, registry: proposal.registry,
      complianceProvider: proposal.complianceProvider, token: proposal.token.address
    },
    identityRef: proposal.identityRef,
    recipient: proposal.recipient.address,
    limits: { ...proposal.limits },
    amounts: { ...proposal.amounts },
    mandateValiditySeconds: proposal.mandateValiditySeconds,
    routes: structuredClone(proposal.routes),
    fees: { ...proposal.fees },
    budgetWei: requiredWei(proposal, LIVE_WRITE_STEPS),
    writes: writeEntries(proposal),
    controls: controlEntries(proposal),
    noncePolicy: 'Each write uses the fresh pending nonce read immediately before preparation. One signature per step. Nonces strictly increase per signer. No replacement, fee bump or re-signature with a different nonce without a new approval.',
    confirmationPolicy: `A step advances after ${proposal.confirmations.stepProgression} confirmations with the same block hash on both read endpoints. The final report requires every block to be finalized on both read endpoints.`,
    cleanup: [
      'If approve succeeded and grant did not, approveReset sets the allowance to zero.',
      'If grant succeeded and the run stopped, revoke ends the mandate and approveReset sets the allowance to zero.',
      'An uncertain owner nonce is resolved from chain evidence before any cleanup write.',
      'A transfer that reached the chain is not reversed by revoke; its effects are reported.'
    ],
    persistentConfiguration: proposal.persistentConfiguration,
    preflight: preflight === null ? null : structuredClone(preflight)
  };
  return Object.freeze({ ...payload, approvalSha256: sha256Canonical(payload) });
}

export function validateRunApproval(value, proposalInput) {
  shape(value, APPROVAL_KEYS, 'APPROVAL_STRUCTURE');
  const rebuilt = buildRunApproval(proposalInput, {
    createdAt: value.createdAt, notAfter: value.notAfter, preflight: value.preflight
  });
  if (canonicalJson(value) !== canonicalJson(rebuilt)) fail('APPROVAL_INTEGRITY');
  return rebuilt;
}
