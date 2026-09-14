// Strict, offline unsigned transaction envelopes. This module has no wallet,
// signing, HTTP, filesystem or broadcast capability.
import {
  KNOWN_PRINCIPAL,
  SEPOLIA_CHAIN_ID,
  canonicalJson,
  sha256Canonical
} from './brickken-intent.mjs';
import {
  PROVISIONED_EXECUTOR,
  decodeSetActionTransferFrom,
  validateOfflineActionSetupCall,
  validateOfflineExecutionCall
} from './brickken-executor.mjs';
import {
  validateOfflineDirectGrantCall,
  validateOfflineDirectRevokeCall
} from './brickken-lifecycle.mjs';
import {
  SANDBOX_IDENTITY_REF,
  validateExecutionPreparation
} from './brickken-prepare.mjs';

export const APPROVE_SELECTOR = '0x095ea7b3';
export const UNSIGNED_ENVELOPE_ACTIONS = Object.freeze([
  'setAction', 'approve', 'grant', 'execute', 'revoke'
]);

const UINT256_MAX = (1n << 256n) - 1n;
const BINDING_KEYS = [
  'nonce', 'type', 'gasLimit', 'maxPriorityFeePerGas', 'maxFeePerGas'
];
const GUARD_KEYS = [
  'identityRef', 'provisioningEvidenceSha256', 'observedAt', 'expiresAt',
  'approvalHash', 'approvedAt', 'approvalExpiresAt', 'maxGasLimit',
  'maxPriorityFeePerGas', 'maxFeePerGas', 'maxTotalGasCost'
];
const TRANSACTION_KEYS = [
  'chainId', 'from', 'to', 'value', 'data', 'nonce', 'gasLimit', 'type',
  'maxPriorityFeePerGas', 'maxFeePerGas'
];
const ENVELOPE_KEYS = [
  'schemaVersion', 'kind', 'action', 'source', 'sourceHash', 'transaction',
  'guard', 'scope', 'envelopeHash'
];
const SET_ACTION_SOURCE_KEYS = ['actionCall'];
const APPROVE_SOURCE_KEYS = ['executionCall', 'approvalAmount'];
const GRANT_SOURCE_KEYS = ['grantCall', 'mandatePlan', 'executionCall', 'reference'];
const REVOKE_SOURCE_KEYS = [
  'revokeCall', 'revokePlan', 'mandatePlan', 'executionCall', 'reference'
];
const EXECUTE_SOURCE_KEYS = [
  'preparation', 'preparationExpectation', 'trustedPreparationHash'
];
const SCOPE_KEYS = [
  'offlineOnly', 'completeTransaction', 'calldataSemanticsValidated',
  'evidenceAndApprovalWindowValid', 'evidenceAuthenticityVerified',
  'approvalAuthenticityVerified', 'trustedExpectationRequired',
  'provisioningReady', 'signingReady', 'chainWriteAuthorized'
];
const SCOPE = Object.freeze({
  offlineOnly: true,
  completeTransaction: true,
  calldataSemanticsValidated: true,
  evidenceAndApprovalWindowValid: true,
  evidenceAuthenticityVerified: false,
  approvalAuthenticityVerified: false,
  trustedExpectationRequired: true,
  provisioningReady: false,
  signingReady: false,
  chainWriteAuthorized: false
});

export class BrickkenEnvelopeError extends Error {
  constructor(code) {
    super(code);
    this.name = 'BrickkenEnvelopeError';
    this.code = code;
  }
}

function fail(code) { throw new BrickkenEnvelopeError(code); }

function strictObject(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.keys(value).length !== keys.length ||
      keys.some(key => !Object.hasOwn(value, key))) fail('STRUCTURE');
}

function uint(value, { positive = false, belowMaximum = false } = {}) {
  let parsed;
  if (typeof value === 'bigint') parsed = value;
  else if (typeof value === 'number' && Number.isSafeInteger(value)) parsed = BigInt(value);
  else if (typeof value === 'string' && value.length <= 78 &&
      (/^(0|[1-9][0-9]*)$/.test(value) || /^0x[0-9a-fA-F]{1,64}$/.test(value))) parsed = BigInt(value);
  else fail('UINT');
  if (parsed < 0n || parsed > UINT256_MAX || (positive && parsed === 0n) ||
      (belowMaximum && parsed === UINT256_MAX)) fail('UINT');
  return parsed;
}

function second(value) {
  if (!Number.isSafeInteger(value) || value <= 0) fail('TIME');
  return value;
}

function hash(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail('HASH');
  return value;
}

function address(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value) || /^0x0{40}$/i.test(value)) {
    fail('ADDRESS');
  }
  return value.toLowerCase();
}

function normalizeGuard(value, nowSeconds) {
  strictObject(value, GUARD_KEYS);
  if (value.identityRef !== SANDBOX_IDENTITY_REF) fail('IDENTITY');
  const observedAt = second(value.observedAt);
  const expiresAt = second(value.expiresAt);
  const approvedAt = second(value.approvedAt);
  const approvalExpiresAt = second(value.approvalExpiresAt);
  const now = second(nowSeconds);
  if (expiresAt <= observedAt || expiresAt - observedAt > 300 ||
      approvalExpiresAt <= approvedAt || approvalExpiresAt - approvedAt > 300 ||
      approvedAt < observedAt || approvedAt >= expiresAt ||
      approvalExpiresAt > expiresAt || now < approvedAt || now >= approvalExpiresAt ||
      now < observedAt || now >= expiresAt) fail('STALE_GUARD');
  const result = {
    identityRef: SANDBOX_IDENTITY_REF,
    provisioningEvidenceSha256: hash(value.provisioningEvidenceSha256),
    observedAt,
    expiresAt,
    approvalHash: hash(value.approvalHash),
    approvedAt,
    approvalExpiresAt
  };
  for (const key of [
    'maxGasLimit', 'maxPriorityFeePerGas', 'maxFeePerGas', 'maxTotalGasCost'
  ]) {
    result[key] = uint(value[key], { positive: true, belowMaximum: true }).toString();
  }
  if (BigInt(result.maxPriorityFeePerGas) > BigInt(result.maxFeePerGas)) fail('RESOURCE_CEILING');
  return Object.freeze(result);
}

function normalizeBinding(value) {
  strictObject(value, BINDING_KEYS);
  if (value.type !== 2) fail('TRANSACTION_TYPE');
  const result = {
    nonce: uint(value.nonce).toString(),
    type: 2,
    gasLimit: uint(value.gasLimit, { positive: true }).toString(),
    maxPriorityFeePerGas: uint(value.maxPriorityFeePerGas).toString(),
    maxFeePerGas: uint(value.maxFeePerGas, { positive: true }).toString()
  };
  if (BigInt(result.maxPriorityFeePerGas) > BigInt(result.maxFeePerGas)) fail('TRANSACTION_FEES');
  return Object.freeze(result);
}

function resourceCheck(transaction, guard) {
  if (BigInt(transaction.gasLimit) > BigInt(guard.maxGasLimit) ||
      BigInt(transaction.maxPriorityFeePerGas) > BigInt(guard.maxPriorityFeePerGas) ||
      BigInt(transaction.maxFeePerGas) > BigInt(guard.maxFeePerGas) ||
      BigInt(transaction.gasLimit) * BigInt(transaction.maxFeePerGas) >
        BigInt(guard.maxTotalGasCost)) fail('RESOURCE_CEILING');
}

function transaction(call, bindingInput, guard) {
  strictObject(call, ['chainId', 'from', 'to', 'value', 'data']);
  const binding = normalizeBinding(bindingInput);
  if (call.chainId !== SEPOLIA_CHAIN_ID || call.value !== '0' ||
      typeof call.data !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(call.data)) fail('CALL');
  const result = Object.freeze({
    chainId: SEPOLIA_CHAIN_ID,
    from: address(call.from),
    to: address(call.to),
    value: '0',
    data: call.data.toLowerCase(),
    nonce: binding.nonce,
    gasLimit: binding.gasLimit,
    type: 2,
    maxPriorityFeePerGas: binding.maxPriorityFeePerGas,
    maxFeePerGas: binding.maxFeePerGas
  });
  resourceCheck(result, guard);
  return result;
}

function addressWord(value) { return '0'.repeat(24) + address(value).slice(2); }
function uintWord(value) { return uint(value).toString(16).padStart(64, '0'); }

export function encodeApproveExecutor(approvalAmount) {
  const amount = uint(approvalAmount, { positive: true, belowMaximum: true });
  return APPROVE_SELECTOR + addressWord(PROVISIONED_EXECUTOR) + uintWord(amount);
}

export function decodeApproveExecutor(value, expectedAmount) {
  if (typeof value !== 'string' || value.length !== 2 + 68 * 2 ||
      !/^0x[0-9a-fA-F]+$/.test(value)) fail('APPROVE_CALLDATA');
  const data = value.toLowerCase();
  if (data.slice(0, 10) !== APPROVE_SELECTOR ||
      data.slice(10, 74) !== addressWord(PROVISIONED_EXECUTOR)) fail('APPROVE_CALLDATA');
  const amount = uint(BigInt('0x' + data.slice(74))).toString();
  if (amount !== uint(expectedAmount, { positive: true, belowMaximum: true }).toString()) {
    fail('APPROVE_AMOUNT');
  }
  return Object.freeze({ spender: PROVISIONED_EXECUTOR, amount });
}

function envelope(action, source, call, bindingInput, guardInput, nowSeconds) {
  const guard = normalizeGuard(guardInput, nowSeconds);
  const completeTransaction = transaction(call, bindingInput, guard);
  const payload = {
    schemaVersion: 1,
    kind: 'rams-unsigned-transaction-envelope',
    action,
    source,
    sourceHash: sha256Canonical(source),
    transaction: completeTransaction,
    guard,
    scope: SCOPE
  };
  return Object.freeze({ ...payload, envelopeHash: sha256Canonical(payload) });
}

export function buildSetActionEnvelope(actionCallInput, bindingInput, guardInput, nowSeconds) {
  const actionCall = validateOfflineActionSetupCall(actionCallInput);
  decodeSetActionTransferFrom(actionCall.call.data);
  return envelope('setAction', Object.freeze({ actionCall }), actionCall.call,
    bindingInput, guardInput, nowSeconds);
}

export function buildApproveEnvelope(executionCallInput, approvalAmount, bindingInput, guardInput, nowSeconds) {
  const executionCall = validateOfflineExecutionCall(executionCallInput);
  const normalizedAmount = uint(approvalAmount, { positive: true, belowMaximum: true }).toString();
  if (normalizedAmount !== executionCall.intent.policy.allowance ||
      BigInt(normalizedAmount) > BigInt(executionCall.intent.policy.maxCumulativeValue)) fail('APPROVAL_BINDING');
  const data = encodeApproveExecutor(normalizedAmount);
  decodeApproveExecutor(data, normalizedAmount);
  const call = Object.freeze({
    chainId: SEPOLIA_CHAIN_ID,
    from: KNOWN_PRINCIPAL,
    to: executionCall.intent.policy.token,
    value: '0',
    data
  });
  return envelope('approve', Object.freeze({ executionCall, approvalAmount: normalizedAmount }),
    call, bindingInput, guardInput, nowSeconds);
}

export function buildGrantEnvelope(inputs, bindingInput, guardInput, nowSeconds) {
  strictObject(inputs, GRANT_SOURCE_KEYS);
  const executionCall = validateOfflineExecutionCall(inputs.executionCall);
  const grantCall = validateOfflineDirectGrantCall(
    inputs.grantCall, inputs.mandatePlan, executionCall, nowSeconds, inputs.reference
  );
  const source = Object.freeze({
    grantCall,
    mandatePlan: inputs.mandatePlan,
    executionCall,
    reference: inputs.reference
  });
  return envelope('grant', source, grantCall.call, bindingInput, guardInput, nowSeconds);
}

export function buildRevokeEnvelope(inputs, bindingInput, guardInput, nowSeconds) {
  strictObject(inputs, REVOKE_SOURCE_KEYS);
  const executionCall = validateOfflineExecutionCall(inputs.executionCall);
  const revokeCall = validateOfflineDirectRevokeCall(
    inputs.revokeCall, inputs.revokePlan, inputs.mandatePlan,
    executionCall, nowSeconds, inputs.reference
  );
  const source = Object.freeze({
    revokeCall,
    revokePlan: inputs.revokePlan,
    mandatePlan: inputs.mandatePlan,
    executionCall,
    reference: inputs.reference
  });
  return envelope('revoke', source, revokeCall.call, bindingInput, guardInput, nowSeconds);
}

export function buildExecuteEnvelope(inputs, bindingInput, guardInput, nowSeconds) {
  strictObject(inputs, EXECUTE_SOURCE_KEYS);
  const preparation = validateExecutionPreparation(
    inputs.preparation, inputs.preparationExpectation, nowSeconds,
    inputs.trustedPreparationHash
  );
  const binding = normalizeBinding(bindingInput);
  for (const key of BINDING_KEYS) {
    if (preparation.transaction[key] !== binding[key]) fail('PREPARATION_BINDING');
  }
  const expectedContext = inputs.preparationExpectation.context;
  const guard = normalizeGuard(guardInput, nowSeconds);
  for (const [guardKey, contextKey] of [
    ['identityRef', 'identityRef'],
    ['provisioningEvidenceSha256', 'provisioningEvidenceSha256'],
    ['observedAt', 'observedAt'],
    ['expiresAt', 'expiresAt'],
    ['maxGasLimit', 'maxGasLimit'],
    ['maxPriorityFeePerGas', 'maxPriorityFeePerGas'],
    ['maxFeePerGas', 'maxFeePerGas'],
    ['maxTotalGasCost', 'maxTotalGasCost']
  ]) {
    if (String(guard[guardKey]) !== String(expectedContext?.[contextKey])) fail('PREPARATION_GUARD');
  }
  const source = Object.freeze({
    preparation,
    preparationExpectation: inputs.preparationExpectation,
    trustedPreparationHash: hash(inputs.trustedPreparationHash)
  });
  const call = Object.freeze({
    chainId: preparation.transaction.chainId,
    from: preparation.transaction.from,
    to: preparation.transaction.to,
    value: preparation.transaction.value,
    data: preparation.transaction.data
  });
  return envelope('execute', source, call, binding, guard, nowSeconds);
}

function bindingFromTransaction(value) {
  strictObject(value, TRANSACTION_KEYS);
  return {
    nonce: value.nonce,
    type: value.type,
    gasLimit: value.gasLimit,
    maxPriorityFeePerGas: value.maxPriorityFeePerGas,
    maxFeePerGas: value.maxFeePerGas
  };
}

function rebuild(value, nowSeconds) {
  strictObject(value, ENVELOPE_KEYS);
  strictObject(value.scope, SCOPE_KEYS);
  if (!UNSIGNED_ENVELOPE_ACTIONS.includes(value.action)) fail('ACTION');
  const binding = bindingFromTransaction(value.transaction);
  switch (value.action) {
    case 'setAction':
      strictObject(value.source, SET_ACTION_SOURCE_KEYS);
      return buildSetActionEnvelope(value.source.actionCall, binding, value.guard, nowSeconds);
    case 'approve':
      strictObject(value.source, APPROVE_SOURCE_KEYS);
      return buildApproveEnvelope(value.source.executionCall, value.source.approvalAmount,
        binding, value.guard, nowSeconds);
    case 'grant':
      strictObject(value.source, GRANT_SOURCE_KEYS);
      return buildGrantEnvelope(value.source, binding, value.guard, nowSeconds);
    case 'revoke':
      strictObject(value.source, REVOKE_SOURCE_KEYS);
      return buildRevokeEnvelope(value.source, binding, value.guard, nowSeconds);
    case 'execute':
      strictObject(value.source, EXECUTE_SOURCE_KEYS);
      return buildExecuteEnvelope(value.source, binding, value.guard, nowSeconds);
    default:
      fail('ACTION');
  }
}

// `trustedExpectation` must come from an independently retained owner-approved
// store. Passing a received envelope as its own expectation checks structure,
// but cannot establish evidence provenance or owner authorization.
export function validateUnsignedEnvelope(value, trustedExpectation, nowSeconds) {
  try {
    const expectation = rebuild(trustedExpectation, nowSeconds);
    if (canonicalJson(trustedExpectation) !== canonicalJson(expectation)) fail('EXPECTATION_INTEGRITY');
    const actual = rebuild({
      ...expectation,
      transaction: value?.transaction,
      source: expectation.source,
      guard: expectation.guard,
      envelopeHash: value?.envelopeHash
    }, nowSeconds);
    if (canonicalJson(value) !== canonicalJson(actual) ||
        canonicalJson(actual) !== canonicalJson(expectation)) fail('ENVELOPE_INTEGRITY');
    return Object.freeze({ expectation, transaction: actual.transaction });
  } catch (error) {
    if (error instanceof BrickkenEnvelopeError) throw error;
    fail('ENVELOPE_REJECTED');
  }
}
