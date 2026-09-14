// Offline direct-principal RAMS request plans; no HTTP or signing capability.
// Sources: docs.brickken.com/api-reference/endpoint/x402-rams-{grant-mandate,revoke-mandate,execute}
import { KNOWN_AGENT, KNOWN_PRINCIPAL, SEPOLIA_CHAIN_ID, TRANSFER_FROM_SELECTOR,
  canonicalJson, sha256Canonical } from './brickken-intent.mjs';
import { validateOfflineExecutionCall, PROVISIONED_EXECUTOR } from './brickken-executor.mjs';
import { SANDBOX_IDENTITY_REF } from './brickken-prepare.mjs';

export const RAMS_REGISTRY = '0xd68e1bb972ca4ef7f5764fbf6d685a6dfc26778e';
const PROVIDER = '0xa90d2503d5d9b80ecc27856ff76f892b8c02f278';
const ORIGIN = 'https://api.sandbox.brickken.com';
const UINT_MAX = (1n << 256n) - 1n;
const SCOPE = Object.freeze({ offlineOnly: true, directPrincipalLifecycleOnly: true,
  recipientEnforcedByLocalIntentOnly: true, lifecycleCalldataVerified: false,
  provisioningReady: false, signingReady: false, chainWriteAuthorized: false });

export class BrickkenMandateError extends Error {
  constructor(code) { super(code); this.name = 'BrickkenMandateError'; this.code = code; }
}
function fail(code) { throw new BrickkenMandateError(code); }
function shape(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
    Object.keys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k))) fail('STRUCTURE');
}
function second(value) {
  if (!Number.isSafeInteger(value) || value <= 0) fail('TIME');
  return value;
}
function window(input, now) {
  shape(input, ['validFrom', 'validUntil']);
  const validFrom = second(input.validFrom), validUntil = second(input.validUntil);
  second(now);
  // Local demo limit: start within five minutes, duration at most one hour.
  if (validFrom < now || validFrom > now + 300 || validUntil <= validFrom || validUntil - validFrom > 3600) fail('WINDOW');
  return Object.freeze({ validFrom, validUntil });
}
function planPayload(call, validity, createdAt) {
  const policy = call.intent.policy;
  for (const key of ['maxTransactionValue', 'maxCumulativeValue', 'allowance']) {
    if (BigInt(policy[key]) === UINT_MAX) fail('UNBOUNDED_AMOUNT');
  }
  if (policy.cumulativeUsed !== '0') fail('NEW_MANDATE_USAGE');
  if (BigInt(policy.allowance) > BigInt(policy.maxCumulativeValue)) fail('ALLOWANCE_EXCEEDS_CAP');
  return {
    schemaVersion: 1, kind: 'rams-direct-mandate-plan', createdAt, callHash: call.callHash,
    intentHash: call.intent.intentHash, policyHash: call.intent.policyHash,
    localRecipient: policy.recipient,
    request: {
      method: 'POST', url: ORIGIN + '/x402/rams/grant-mandate',
      body: {
        chainId: SEPOLIA_CHAIN_ID, principal: KNOWN_PRINCIPAL, agent: KNOWN_AGENT,
        signerAddress: KNOWN_PRINCIPAL, agentMandateAddress: RAMS_REGISTRY,
        complianceProvider: PROVIDER, identityRef: SANDBOX_IDENTITY_REF,
        asset: policy.token, actions: [TRANSFER_FROM_SELECTOR],
        maxTransactionValue: policy.maxTransactionValue, maxCumulativeValue: policy.maxCumulativeValue,
        validFrom: validity.validFrom, validUntil: validity.validUntil
      }
    },
    scope: SCOPE
  };
}
export function buildDirectMandatePlan(callInput, validityInput, nowSeconds) {
  const call = validateOfflineExecutionCall(callInput);
  const validity = window(validityInput, nowSeconds);
  const payload = planPayload(call, validity, second(nowSeconds));
  return { ...payload, planHash: sha256Canonical(payload) };
}
export function validateDirectMandatePlan(plan, callInput, nowSeconds) {
  const call = validateOfflineExecutionCall(callInput);
  shape(plan, ['schemaVersion', 'kind', 'createdAt', 'callHash', 'intentHash', 'policyHash', 'localRecipient', 'request', 'scope', 'planHash']);
  const body = plan.request?.body;
  if (!body) fail('PLAN');
  // Retain the construction reference time instead of resetting it to the
  // requested start. This remains a local caller assertion, not a signed clock.
  const rebuilt = buildDirectMandatePlan(call, { validFrom: body.validFrom, validUntil: body.validUntil }, plan.createdAt);
  if (canonicalJson(plan) !== canonicalJson(rebuilt)) fail('PLAN_INTEGRITY');
  const now = second(nowSeconds);
  if (now < body.validFrom || now >= body.validUntil) fail('MANDATE_WINDOW');
  return rebuilt;
}
export function buildDirectRevokePlan() {
  const payload = {
    schemaVersion: 1, kind: 'rams-direct-revoke-plan',
    request: { method: 'POST', url: ORIGIN + '/x402/rams/revoke-mandate', body: {
      chainId: SEPOLIA_CHAIN_ID, principal: KNOWN_PRINCIPAL, agent: KNOWN_AGENT,
      signerAddress: KNOWN_PRINCIPAL, agentMandateAddress: RAMS_REGISTRY
    } }, scope: SCOPE
  };
  return { ...payload, planHash: sha256Canonical(payload) };
}
export function buildExecutePrepareRequest(callInput, mandatePlan, nowSeconds) {
  const call = validateOfflineExecutionCall(callInput);
  const mandate = validateDirectMandatePlan(mandatePlan, call, nowSeconds);
  const payload = {
    schemaVersion: 1, kind: 'rams-helper-execute-request', callHash: call.callHash, mandatePlanHash: mandate.planHash,
    request: { method: 'POST', url: ORIGIN + '/x402/rams/execute', body: {
      chainId: SEPOLIA_CHAIN_ID, signerAddress: KNOWN_AGENT, executorAddress: PROVISIONED_EXECUTOR,
      asset: call.intent.policy.token, from: KNOWN_PRINCIPAL,
      to: call.intent.policy.recipient, amount: call.intent.transfer.amount
    } }, scope: SCOPE
  };
  return { ...payload, requestHash: sha256Canonical(payload) };
}
