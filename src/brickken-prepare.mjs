// Offline, fail-closed prepare-response boundary. No HTTP, signing or storage.
// Wire envelope: https://docs.brickken.com/api-reference/endpoint/create
// Numeric BigNumber form: .../endpoint/prepare-transferFrom
import {
  buildExpectedUnsignedTransaction, canonicalJson, sha256Canonical,
  validatePreparedTransactions
} from './brickken-intent.mjs';
import { validateOfflineExecutionCall, decodeExecutorExecute } from './brickken-executor.mjs';

export const SANDBOX_IDENTITY_REF = '0x6cc959e8598e56ce16688ac27025da562401e5a85fd3814d27ed69800f1f7633';
const MAX_BODY_BYTES = 65536;
const UINT_MAX = (1n << 256n) - 1n;
const TX_KEYS = ['chainId', 'from', 'to', 'value', 'data', 'nonce', 'gasLimit', 'type', 'maxPriorityFeePerGas', 'maxFeePerGas'];
const NUMERIC_KEYS = ['chainId', 'value', 'nonce', 'gasLimit', 'maxPriorityFeePerGas', 'maxFeePerGas'];
const CONTEXT_KEYS = ['identityRef', 'provisioningEvidenceSha256', 'observedAt', 'expiresAt', 'maxGasLimit', 'maxPriorityFeePerGas', 'maxFeePerGas', 'maxTotalGasCost'];
const PREPARATION_KEYS = [
  'schemaVersion', 'kind', 'txId', 'transactionsContainerShape', 'transaction',
  'expectationHash', 'identityRef', 'provisioningEvidenceSha256', 'expiresAt',
  'scope', 'preparationHash'
];
const SCOPE = Object.freeze({ offlineOnly: true, abiSemanticsValidated: true, evidenceReferenceOnly: true,
  livePrepareObserved: false, provisioningReady: false, signingReady: false, chainWriteAuthorized: false });

export class BrickkenPrepareError extends Error {
  constructor(code) { super(code); this.name = 'BrickkenPrepareError'; this.code = code; }
}
function fail(code) { throw new BrickkenPrepareError(code); }
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value));
}
function shape(value, keys) {
  if (!plain(value) || Object.keys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k))) fail('STRUCTURE');
}
function uint(value) {
  if (plain(value)) {
    shape(value, ['type', 'hex']);
    if (value.type !== 'BigNumber' || typeof value.hex !== 'string' || !/^0x[0-9a-fA-F]{1,64}$/.test(value.hex)) fail('UINT');
    value = value.hex;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('UINT');
  } else if (typeof value !== 'string' || value.length > 78 ||
    !(/^(0|[1-9][0-9]*)$/.test(value) || /^0x[0-9a-fA-F]{1,64}$/.test(value))) fail('UINT');
  const result = BigInt(value);
  if (result < 0n || result > UINT_MAX) fail('UINT');
  return result.toString();
}
function second(value) {
  if (!Number.isSafeInteger(value) || value <= 0) fail('TIME');
  return value;
}
function context(input) {
  shape(input, CONTEXT_KEYS);
  if (input.identityRef !== SANDBOX_IDENTITY_REF ||
    typeof input.provisioningEvidenceSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(input.provisioningEvidenceSha256)) fail('CONTEXT_BINDING');
  const observedAt = second(input.observedAt), expiresAt = second(input.expiresAt);
  // Five minutes is a local ceiling, not a Brickken protocol rule.
  if (expiresAt <= observedAt || expiresAt - observedAt > 300) fail('EVIDENCE_WINDOW');
  const result = { ...input, observedAt, expiresAt };
  for (const key of ['maxGasLimit', 'maxPriorityFeePerGas', 'maxFeePerGas', 'maxTotalGasCost']) {
    result[key] = uint(input[key]);
    if (result[key] === '0') fail('RESOURCE_CEILING');
  }
  if (BigInt(result.maxPriorityFeePerGas) > BigInt(result.maxFeePerGas)) fail('RESOURCE_CEILING');
  return Object.freeze(result);
}
function resourceCheck(tx, limits) {
  if (BigInt(tx.gasLimit) > BigInt(limits.maxGasLimit) ||
      BigInt(tx.maxPriorityFeePerGas) > BigInt(limits.maxPriorityFeePerGas) ||
      BigInt(tx.maxFeePerGas) > BigInt(limits.maxFeePerGas) ||
      BigInt(tx.maxPriorityFeePerGas) > BigInt(tx.maxFeePerGas) ||
      BigInt(tx.gasLimit) * BigInt(tx.maxFeePerGas) > BigInt(limits.maxTotalGasCost)) fail('RESOURCE_CEILING');
}

// The exact nonce comes from an independent chain observation. The gas limit,
// priority fee and maximum fee in the expected transaction are caller-selected
// ceilings from the reviewed context, never values copied from the response.
// maxTotalGasCost may be tighter than maxGasLimit * maxFeePerGas. Building
// that context is valid; the actual response must satisfy all four ceilings.
// The expected gas fields are limits, not a promise of an admissible response.
// A hash associates evidence only; this pure function cannot establish that
// evidence is authentic or current.
export function buildExpectedExecutionPreparation(callInput, binding, contextInput) {
  const call = validateOfflineExecutionCall(callInput);
  shape(binding, ['nonce', 'type']);
  const limits = context(contextInput);
  const expected = buildExpectedUnsignedTransaction(call.intent, {
    ...binding,
    outerCalldata: call.call.data,
    gasLimit: limits.maxGasLimit,
    maxPriorityFeePerGas: limits.maxPriorityFeePerGas,
    maxFeePerGas: limits.maxFeePerGas
  });
  const payload = { schemaVersion: 1, kind: 'rams-execute-prepare-expectation', call, expected, context: limits, scope: SCOPE };
  return Object.freeze({ ...payload, expectationHash: sha256Canonical(payload) });
}
function validateExpectation(value) {
  shape(value, ['schemaVersion', 'kind', 'call', 'expected', 'context', 'scope', 'expectationHash']);
  const tx = value.expected?.transaction;
  if (!plain(tx)) fail('EXPECTATION');
  const rebuilt = buildExpectedExecutionPreparation(value.call, {
    nonce: tx.nonce, type: tx.type
  }, value.context);
  if (canonicalJson(value) !== canonicalJson(rebuilt)) fail('EXPECTATION_INTEGRITY');
  return rebuilt;
}
function normalizeWireTransaction(value) {
  shape(value, TX_KEYS);
  const tx = { ...value };
  for (const key of NUMERIC_KEYS) tx[key] = uint(value[key]);
  // Only the documented exact integer discriminant is supported.
  if (value.type !== 2) fail('TRANSACTION_TYPE');
  return tx;
}

function buildValidatedExecutionPreparation(transactionInput, txId, transactionsContainerShape, expectation, nowSeconds) {
  const expected = validateExpectation(expectation);
  const now = second(nowSeconds);
  if (now < expected.context.observedAt || now >= expected.context.expiresAt) fail('EXPECTATION_EXPIRED');
  if (typeof txId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(txId)) fail('TX_ID');
  if (!['array', 'object'].includes(transactionsContainerShape)) fail('ENVELOPE');
  const tx = normalizeWireTransaction(transactionInput);
  const validated = validatePreparedTransactions([tx], expected.expected, {
    gasLimit: expected.context.maxGasLimit,
    maxPriorityFeePerGas: expected.context.maxPriorityFeePerGas,
    maxFeePerGas: expected.context.maxFeePerGas
  });
  decodeExecutorExecute(validated.transaction.data, expected.call.intent);
  resourceCheck(validated.transaction, expected.context);
  const payload = {
    schemaVersion: 1, kind: 'validated-rams-execute-preparation', txId,
    transactionsContainerShape,
    transaction: validated.transaction, expectationHash: expected.expectationHash,
    identityRef: expected.context.identityRef,
    provisioningEvidenceSha256: expected.context.provisioningEvidenceSha256,
    expiresAt: expected.context.expiresAt, scope: SCOPE
  };
  return Object.freeze({ ...payload, preparationHash: sha256Canonical(payload) });
}

// Revalidate a received or persisted preparation immediately before it is
// passed to a signing boundary. The separately supplied expectation is the
// trusted input: hashes contained in `value` never select identities, calldata,
// ceilings or validity. The returned object is a complete canonical rebuild.
export function validateExecutionPreparation(value, expectationInput, nowSeconds, trustedPreparationHash) {
  try {
    if (typeof trustedPreparationHash !== 'string' ||
        !/^[a-f0-9]{64}$/.test(trustedPreparationHash)) fail('TRUSTED_PREPARATION_HASH');
    shape(value, PREPARATION_KEYS);
    const rebuilt = buildValidatedExecutionPreparation(
      value.transaction,
      value.txId,
      value.transactionsContainerShape,
      expectationInput,
      nowSeconds
    );
    if (canonicalJson(value) !== canonicalJson(rebuilt) ||
        rebuilt.preparationHash !== trustedPreparationHash) fail('PREPARATION_INTEGRITY');
    return rebuilt;
  } catch (error) {
    if (error instanceof BrickkenPrepareError) throw error;
    fail('PREPARATION_REJECTED');
  }
}

// Generic prepare documents a root container; RAMS documents a data envelope.
// Accept exactly one of these, never fall back from a malformed wrapper.
// RAMS endpoints document one transaction object, while generic prepare uses a
// transaction array. Accept one closed transaction in either form. Payment
// offers stop here.
export function validateExecutePrepareResponse(body, expectationInput, nowSeconds) {
  try {
    if (typeof body !== 'string' || Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) fail('BODY_SIZE');
    const root = JSON.parse(body);
    if (!plain(root)) fail('ENVELOPE');
    if (Object.hasOwn(root, 'x402Requirements')) fail('PAYMENT_REVIEW_REQUIRED');
    let json = root;
    if (Object.hasOwn(root, 'data')) {
      shape(root, ['data']);
      json = root.data;
      if (!plain(json)) fail('ENVELOPE');
      if (Object.hasOwn(json, 'x402Requirements')) fail('PAYMENT_REVIEW_REQUIRED');
    }
    const keys = Object.hasOwn(json, 'info') ? ['transactions', 'txId', 'info'] : ['transactions', 'txId'];
    shape(json, keys);
    if (Object.hasOwn(json, 'info') && !plain(json.info)) fail('INFO');
    let transactionInput;
    let transactionsContainerShape;
    if (Array.isArray(json.transactions)) {
      if (json.transactions.length !== 1) fail('BATCH_REJECTED');
      transactionInput = json.transactions[0];
      transactionsContainerShape = 'array';
    } else if (plain(json.transactions)) {
      transactionInput = json.transactions;
      transactionsContainerShape = 'object';
    } else fail('BATCH_REJECTED');
    // Metadata is deliberately not forwarded. txId is a batch identifier, not
    // a blockchain transaction hash. No signature exists at this boundary.
    return buildValidatedExecutionPreparation(
      transactionInput, json.txId, transactionsContainerShape, expectationInput, nowSeconds
    );
  } catch (error) {
    if (error instanceof BrickkenPrepareError) throw error;
    // Never echo an API response or a caller-supplied field through diagnostics.
    fail('PREPARATION_REJECTED');
  }
}
