// Exact offline calldata for the verified Sepolia AgentMandate deployment.
// No HTTP, wallet, signing, filesystem or chain-write capability.
// ABI/source:
// https://eth-sepolia.blockscout.com/api/v2/smart-contracts/0xd68e1bb972ca4ef7f5764fbf6d685a6dfc26778e
// https://sourcify.dev/server/v2/contract/11155111/0xd68e1bb972ca4ef7f5764fbf6d685a6dfc26778e
import {
  KNOWN_AGENT,
  KNOWN_PRINCIPAL,
  SEPOLIA_CHAIN_ID,
  TRANSFER_FROM_ACTION,
  canonicalJson,
  sha256Canonical
} from './brickken-intent.mjs';
import { validateOfflineExecutionCall } from './brickken-executor.mjs';
import {
  RAMS_REGISTRY,
  buildDirectRevokePlan,
  validateDirectMandatePlan
} from './brickken-mandate.mjs';

export const GRANT_MANDATE_SELECTOR = '0xc6a4ad00';
export const REVOKE_MANDATE_SELECTOR = '0x5e20639e';
export const DIRECT_LIFECYCLE_DEADLINE = '0';
export const EMPTY_SIGNATURE = '0x';
export const EMPTY_METADATA = '0x' + '0'.repeat(64);

const COMPLIANCE_PROVIDER = '0xa90d2503d5d9b80ecc27856ff76f892b8c02f278';
const UINT48_MAX = (1n << 48n) - 1n;
const UINT256_MAX = (1n << 256n) - 1n;
const ZERO_WORD = '0'.repeat(64);
const GRANT_BYTES = 548;
const REVOKE_BYTES = 164;
const GRANT_REFERENCE_KEYS = [
  'schemaVersion', 'kind', 'mandatePlanHash', 'executionCallHash', 'registry',
  'caller', 'agent', 'principal', 'complianceProvider', 'identityRef', 'asset',
  'maxTransactionValue', 'maxCumulativeValue', 'validFrom', 'validUntil',
  'metadata', 'actions', 'deadline', 'signature'
];
const REVOKE_REFERENCE_KEYS = [
  'schemaVersion', 'kind', 'revokePlanHash', 'mandatePlanHash', 'registry',
  'caller', 'agent', 'principal', 'deadline', 'signature'
];
const CALL_KEYS = ['chainId', 'from', 'to', 'value', 'data'];
const SCOPE_KEYS = [
  'offlineOnly', 'directPrincipalOnly', 'lifecycleCalldataVerified',
  'provisioningReady', 'signingReady', 'chainWriteAuthorized'
];
const ARTIFACT_KEYS = [
  'schemaVersion', 'kind', 'mandatePlanHash', 'referenceHash', 'call', 'decoded',
  'scope', 'outerCalldataHash', 'lifecycleCallHash'
];
const REVOKE_ARTIFACT_KEYS = [
  'schemaVersion', 'kind', 'revokePlanHash', 'mandatePlanHash', 'referenceHash',
  'call', 'decoded', 'scope', 'outerCalldataHash', 'lifecycleCallHash'
];
const SCOPE = Object.freeze({
  offlineOnly: true,
  directPrincipalOnly: true,
  lifecycleCalldataVerified: true,
  provisioningReady: false,
  signingReady: false,
  chainWriteAuthorized: false
});

export class BrickkenLifecycleError extends Error {
  constructor(code) { super(code); this.name = 'BrickkenLifecycleError'; this.code = code; }
}
function fail(code) { throw new BrickkenLifecycleError(code); }
function strictObject(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.keys(value).length !== keys.length ||
      keys.some(key => !Object.hasOwn(value, key))) fail('STRUCTURE');
}
function exactHex(value, bytes) {
  if (typeof value !== 'string' || value.length !== 2 + bytes * 2 ||
      !/^0x[0-9a-fA-F]*$/.test(value)) fail('CALLDATA');
  return value.toLowerCase();
}
function uint(value, bits = 256) {
  let parsed;
  if (typeof value === 'bigint') parsed = value;
  else if (typeof value === 'number' && Number.isSafeInteger(value)) parsed = BigInt(value);
  else if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && value.length <= 78) parsed = BigInt(value);
  else fail('INTEGER');
  const maximum = bits === 48 ? UINT48_MAX : UINT256_MAX;
  if (parsed < 0n || parsed > maximum) fail('INTEGER_WIDTH');
  return parsed;
}
function word(value, bits = 256) { return uint(value, bits).toString(16).padStart(64, '0'); }
function address(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value) || /^0x0{40}$/i.test(value)) fail('ADDRESS');
  return value.toLowerCase();
}
function addressWord(value) { return '0'.repeat(24) + address(value).slice(2); }
function decodeAddressWord(value) {
  if (value.length !== 64 || !value.startsWith('0'.repeat(24))) fail('PADDING');
  return address('0x' + value.slice(24));
}
function decodeUintWord(value, bits = 256) {
  if (!/^[0-9a-f]{64}$/.test(value)) fail('CALLDATA');
  return uint(BigInt('0x' + value), bits).toString();
}
function bodyOf(plan) {
  const body = plan?.request?.body;
  if (!body) fail('PLAN');
  return body;
}
function safeNow(value) {
  if (!Number.isSafeInteger(value) || value <= 0) fail('TIME');
  return value;
}
function expectedGrantReference(plan, call) {
  const body = bodyOf(plan);
  return Object.freeze({
    schemaVersion: 1,
    kind: 'rams-direct-grant-reference',
    mandatePlanHash: plan.planHash,
    executionCallHash: call.callHash,
    registry: RAMS_REGISTRY,
    caller: KNOWN_PRINCIPAL,
    agent: KNOWN_AGENT,
    principal: KNOWN_PRINCIPAL,
    complianceProvider: COMPLIANCE_PROVIDER,
    identityRef: body.identityRef,
    asset: call.intent.policy.token,
    maxTransactionValue: call.intent.policy.maxTransactionValue,
    maxCumulativeValue: call.intent.policy.maxCumulativeValue,
    validFrom: body.validFrom,
    validUntil: body.validUntil,
    metadata: EMPTY_METADATA,
    actions: Object.freeze([TRANSFER_FROM_ACTION]),
    deadline: DIRECT_LIFECYCLE_DEADLINE,
    signature: EMPTY_SIGNATURE
  });
}
function checkedGrantInputs(planInput, callInput, nowSeconds, referenceInput) {
  const now = safeNow(nowSeconds);
  const call = validateOfflineExecutionCall(callInput);
  const suppliedBody = bodyOf(planInput);
  // The direct on-chain grant may establish a mandate whose validFrom is in
  // the future. Validate plan construction at that boundary, then constrain
  // preparation to the plan's own creation/expiry interval. Execution retains
  // the stricter active-window check in validateDirectMandatePlan.
  const plan = validateDirectMandatePlan(planInput, call, suppliedBody.validFrom);
  const body = bodyOf(plan);
  if (now < plan.createdAt || now >= body.validUntil) fail('MANDATE_WINDOW');
  strictObject(referenceInput, GRANT_REFERENCE_KEYS);
  const reference = expectedGrantReference(plan, call);
  if (canonicalJson(referenceInput) !== canonicalJson(reference)) fail('REFERENCE_MISMATCH');
  if (bodyOf(plan).agentMandateAddress !== RAMS_REGISTRY ||
      bodyOf(plan).signerAddress !== KNOWN_PRINCIPAL ||
      bodyOf(plan).complianceProvider !== COMPLIANCE_PROVIDER) fail('PLAN_BINDING');
  return { plan, call, reference };
}
function checkedRevokeInputs(revokePlanInput, mandatePlanInput, callInput, nowSeconds, referenceInput) {
  safeNow(nowSeconds);
  const call = validateOfflineExecutionCall(callInput);
  const suppliedBody = bodyOf(mandatePlanInput);
  // On-chain revokeMandate does not require the mandate to be inside its
  // validity window. Validate the independent plan's construction and hashes
  // at its own validFrom boundary, while retaining a strict caller time input.
  const mandate = validateDirectMandatePlan(mandatePlanInput, call, suppliedBody.validFrom);
  const expectedRevoke = buildDirectRevokePlan();
  if (canonicalJson(revokePlanInput) !== canonicalJson(expectedRevoke)) fail('REVOKE_PLAN');
  const expected = Object.freeze({
    schemaVersion: 1,
    kind: 'rams-direct-revoke-reference',
    revokePlanHash: expectedRevoke.planHash,
    mandatePlanHash: mandate.planHash,
    registry: RAMS_REGISTRY,
    caller: KNOWN_PRINCIPAL,
    agent: KNOWN_AGENT,
    principal: KNOWN_PRINCIPAL,
    deadline: DIRECT_LIFECYCLE_DEADLINE,
    signature: EMPTY_SIGNATURE
  });
  strictObject(referenceInput, REVOKE_REFERENCE_KEYS);
  if (canonicalJson(referenceInput) !== canonicalJson(expected)) fail('REFERENCE_MISMATCH');
  const body = bodyOf(expectedRevoke);
  if (body.agentMandateAddress !== RAMS_REGISTRY || body.signerAddress !== KNOWN_PRINCIPAL) fail('PLAN_BINDING');
  return { revokePlan: expectedRevoke, mandate, call, reference: expected };
}

export function encodeDirectGrantMandateCalldata(planInput, callInput, nowSeconds, referenceInput) {
  const { reference } = checkedGrantInputs(planInput, callInput, nowSeconds, referenceInput);
  const tupleHead = [
    addressWord(reference.agent),
    word(reference.validFrom, 48),
    word(reference.validUntil, 48),
    addressWord(reference.principal),
    addressWord(reference.complianceProvider),
    exactHex(reference.identityRef, 32).slice(2),
    addressWord(reference.asset),
    word(reference.maxTransactionValue),
    word(reference.maxCumulativeValue),
    exactHex(reference.metadata, 32).slice(2),
    word(384),
    word(reference.deadline)
  ].join('');
  return GRANT_MANDATE_SELECTOR + word(64) + word(512) + tupleHead +
    word(1) + exactHex(reference.actions[0], 32).slice(2) + word(0);
}

export function decodeDirectGrantMandateCalldata(value, planInput, callInput, nowSeconds, referenceInput) {
  const { reference } = checkedGrantInputs(planInput, callInput, nowSeconds, referenceInput);
  const data = exactHex(value, GRANT_BYTES);
  if (data.slice(0, 10) !== GRANT_MANDATE_SELECTOR) fail('SELECTOR');
  const args = data.slice(10);
  const words = Array.from({ length: 17 }, (_, index) => args.slice(index * 64, (index + 1) * 64));
  if (words[0] !== word(64) || words[1] !== word(512) || words[12] !== word(384) ||
      words[14] !== word(1) || words[16] !== ZERO_WORD) fail('OFFSET_OR_LENGTH');
  const decoded = Object.freeze({
    agent: decodeAddressWord(words[2]),
    validFrom: decodeUintWord(words[3], 48),
    validUntil: decodeUintWord(words[4], 48),
    principal: decodeAddressWord(words[5]),
    complianceProvider: decodeAddressWord(words[6]),
    identityRef: '0x' + words[7],
    asset: decodeAddressWord(words[8]),
    maxTransactionValue: decodeUintWord(words[9]),
    maxCumulativeValue: decodeUintWord(words[10]),
    metadata: '0x' + words[11],
    actions: Object.freeze(['0x' + words[15]]),
    deadline: decodeUintWord(words[13]),
    signature: EMPTY_SIGNATURE
  });
  const expected = {
    agent: reference.agent,
    validFrom: String(reference.validFrom),
    validUntil: String(reference.validUntil),
    principal: reference.principal,
    complianceProvider: reference.complianceProvider,
    identityRef: reference.identityRef,
    asset: reference.asset,
    maxTransactionValue: reference.maxTransactionValue,
    maxCumulativeValue: reference.maxCumulativeValue,
    metadata: reference.metadata,
    actions: reference.actions,
    deadline: reference.deadline,
    signature: reference.signature
  };
  if (canonicalJson(decoded) !== canonicalJson(expected)) fail('CALL_MISMATCH');
  return decoded;
}

export function encodeDirectRevokeMandateCalldata(revokePlanInput, mandatePlanInput, callInput, nowSeconds, referenceInput) {
  const { reference } = checkedRevokeInputs(revokePlanInput, mandatePlanInput, callInput, nowSeconds, referenceInput);
  return REVOKE_MANDATE_SELECTOR + addressWord(reference.agent) + addressWord(reference.principal) +
    word(reference.deadline) + word(128) + word(0);
}

export function decodeDirectRevokeMandateCalldata(value, revokePlanInput, mandatePlanInput, callInput, nowSeconds, referenceInput) {
  const { reference } = checkedRevokeInputs(revokePlanInput, mandatePlanInput, callInput, nowSeconds, referenceInput);
  const data = exactHex(value, REVOKE_BYTES);
  if (data.slice(0, 10) !== REVOKE_MANDATE_SELECTOR) fail('SELECTOR');
  const args = data.slice(10);
  const words = Array.from({ length: 5 }, (_, index) => args.slice(index * 64, (index + 1) * 64));
  if (words[3] !== word(128) || words[4] !== ZERO_WORD) fail('OFFSET_OR_LENGTH');
  const decoded = Object.freeze({
    agent: decodeAddressWord(words[0]),
    principal: decodeAddressWord(words[1]),
    deadline: decodeUintWord(words[2]),
    signature: EMPTY_SIGNATURE
  });
  const expected = {
    agent: reference.agent,
    principal: reference.principal,
    deadline: reference.deadline,
    signature: reference.signature
  };
  if (canonicalJson(decoded) !== canonicalJson(expected)) fail('CALL_MISMATCH');
  return decoded;
}

function fixedCall(data) {
  return Object.freeze({ chainId: SEPOLIA_CHAIN_ID, from: KNOWN_PRINCIPAL,
    to: RAMS_REGISTRY, value: '0', data });
}
function validateCall(value, expectedData) {
  strictObject(value, CALL_KEYS);
  if (value.chainId !== SEPOLIA_CHAIN_ID || value.from !== KNOWN_PRINCIPAL ||
      value.to !== RAMS_REGISTRY || value.value !== '0' || value.data !== expectedData) fail('CALL_MISMATCH');
}

export function buildOfflineDirectGrantCall(planInput, callInput, nowSeconds, referenceInput) {
  const checked = checkedGrantInputs(planInput, callInput, nowSeconds, referenceInput);
  const data = encodeDirectGrantMandateCalldata(checked.plan, checked.call, nowSeconds, checked.reference);
  const decoded = decodeDirectGrantMandateCalldata(data, checked.plan, checked.call, nowSeconds, checked.reference);
  const call = fixedCall(data);
  const payload = Object.freeze({
    schemaVersion: 1,
    kind: 'rams-offline-direct-grant-call',
    mandatePlanHash: checked.plan.planHash,
    referenceHash: sha256Canonical(checked.reference),
    call,
    decoded,
    scope: SCOPE,
    outerCalldataHash: sha256Canonical(data)
  });
  return Object.freeze({ ...payload, lifecycleCallHash: sha256Canonical(payload) });
}

export function validateOfflineDirectGrantCall(value, planInput, callInput, nowSeconds, referenceInput) {
  strictObject(value, ARTIFACT_KEYS);
  strictObject(value.scope, SCOPE_KEYS);
  const expectedData = encodeDirectGrantMandateCalldata(planInput, callInput, nowSeconds, referenceInput);
  decodeDirectGrantMandateCalldata(value.call?.data, planInput, callInput, nowSeconds, referenceInput);
  validateCall(value.call, expectedData);
  const rebuilt = buildOfflineDirectGrantCall(planInput, callInput, nowSeconds, referenceInput);
  if (canonicalJson(value) !== canonicalJson(rebuilt)) fail('ARTIFACT_INTEGRITY');
  return rebuilt;
}

export function buildOfflineDirectRevokeCall(revokePlanInput, mandatePlanInput, callInput, nowSeconds, referenceInput) {
  const checked = checkedRevokeInputs(revokePlanInput, mandatePlanInput, callInput, nowSeconds, referenceInput);
  const data = encodeDirectRevokeMandateCalldata(checked.revokePlan, checked.mandate, checked.call, nowSeconds, checked.reference);
  const decoded = decodeDirectRevokeMandateCalldata(data, checked.revokePlan, checked.mandate, checked.call, nowSeconds, checked.reference);
  const call = fixedCall(data);
  const payload = Object.freeze({
    schemaVersion: 1,
    kind: 'rams-offline-direct-revoke-call',
    revokePlanHash: checked.revokePlan.planHash,
    mandatePlanHash: checked.mandate.planHash,
    referenceHash: sha256Canonical(checked.reference),
    call,
    decoded,
    scope: SCOPE,
    outerCalldataHash: sha256Canonical(data)
  });
  return Object.freeze({ ...payload, lifecycleCallHash: sha256Canonical(payload) });
}

export function validateOfflineDirectRevokeCall(value, revokePlanInput, mandatePlanInput, callInput, nowSeconds, referenceInput) {
  strictObject(value, REVOKE_ARTIFACT_KEYS);
  strictObject(value.scope, SCOPE_KEYS);
  const expectedData = encodeDirectRevokeMandateCalldata(revokePlanInput, mandatePlanInput, callInput, nowSeconds, referenceInput);
  decodeDirectRevokeMandateCalldata(value.call?.data, revokePlanInput, mandatePlanInput, callInput, nowSeconds, referenceInput);
  validateCall(value.call, expectedData);
  const rebuilt = buildOfflineDirectRevokeCall(revokePlanInput, mandatePlanInput, callInput, nowSeconds, referenceInput);
  if (canonicalJson(value) !== canonicalJson(rebuilt)) fail('ARTIFACT_INTEGRITY');
  return rebuilt;
}
