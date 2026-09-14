import { createHash } from 'node:crypto';

export const SEPOLIA_CHAIN_ID = '11155111';
export const KNOWN_PRINCIPAL = '0x1f5ed27aef8367bc8ea936ec562b776a1399e5d4';
export const KNOWN_AGENT = '0x18ff8b19e9e9cc35c7f10b1c690bb84d56cc9442';
export const PLATFORM_DEFAULT_EXECUTOR = '0xc81949cf5b52bdc7890fd5040a9cd0cdb4b59952';
export const TRANSFER_FROM_SELECTOR = '0x23b872dd';
export const TRANSFER_FROM_ACTION = TRANSFER_FROM_SELECTOR + '0'.repeat(56);
export const TRANSFER_FROM_AMOUNT_INDEX = 2;

const UINT256_MAX = (1n << 256n) - 1n;
const POLICY_KEYS = [
  'chainId', 'principal', 'agent', 'executor', 'token', 'recipient', 'action',
  'maxTransactionValue', 'maxCumulativeValue', 'cumulativeUsed', 'allowance'
];
const ACTION_KEYS = ['selector', 'supported', 'hasAmount', 'amountIndex'];
const TRANSFER_KEYS = ['from', 'to', 'amount'];
const INTENT_KEYS = [
  'schemaVersion', 'kind', 'policy', 'transfer', 'innerCalldata', 'scope',
  'policyHash', 'intentHash'
];
const INTENT_SCOPE_KEYS = [
  'offlineOnly', 'chainWriteAuthorized', 'outerEncoderAvailable',
  'executorBindingVerified'
];
const BINDING_KEYS = [
  'outerCalldata', 'nonce', 'gasLimit', 'type', 'maxPriorityFeePerGas',
  'maxFeePerGas'
];
const TRANSACTION_KEYS = [
  'chainId', 'from', 'to', 'value', 'data', 'nonce', 'gasLimit', 'type',
  'maxPriorityFeePerGas', 'maxFeePerGas'
];
const EXACT_PREPARED_TRANSACTION_KEYS = ['chainId', 'from', 'to', 'value', 'data', 'nonce', 'type'];
const PREPARED_TRANSACTION_CEILING_KEYS = ['gasLimit', 'maxPriorityFeePerGas', 'maxFeePerGas'];
const EXPECTED_KEYS = [
  'schemaVersion', 'kind', 'intent', 'transaction', 'scope',
  'transactionIntentHash'
];
const EXPECTED_SCOPE_KEYS = [
  'offlineOnly', 'chainWriteAuthorized', 'outerEncoderAvailable',
  'outerCalldataVerified', 'signingReady'
];

export class BrickkenIntentError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrickkenIntentError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new BrickkenIntentError(code, message);
}

function strictObject(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
      Object.keys(value).length !== keys.length ||
      keys.some(key => !(key in value)) ||
      Object.keys(value).some(key => !keys.includes(key))) {
    fail('INVALID_STRUCTURE', `${label} fields do not match the allowed structure.`);
  }
}

function normalizeAddress(value, label) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value) || /^0x0{40}$/i.test(value)) {
    fail('INVALID_ADDRESS', `${label} must be a nonzero Ethereum address.`);
  }
  return value.toLowerCase();
}

function normalizeUint(value, label, { positive = false } = {}) {
  let amount;
  if (typeof value === 'bigint') amount = value;
  else if (typeof value === 'number' && Number.isSafeInteger(value)) amount = BigInt(value);
  else if (typeof value === 'string') {
    const decimal = value.length <= 78 && /^(0|[1-9][0-9]*)$/.test(value);
    const hexadecimal = value.length <= 66 && /^0x[0-9a-fA-F]+$/.test(value);
    if (!decimal && !hexadecimal) fail('INVALID_UINT', `${label} must be an exact unsigned integer.`);
    amount = BigInt(value);
  } else fail('INVALID_UINT', `${label} must be an exact unsigned integer.`);
  if (amount < 0n || amount > UINT256_MAX || (positive && amount === 0n)) {
    fail('INVALID_UINT', `${label} is outside the permitted uint256 range.`);
  }
  return amount;
}

function normalizeHex(value, label, { minBytes = 0, exactBytes } = {}) {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(value)) {
    fail('INVALID_CALLDATA', `${label} must be byte-aligned hexadecimal data.`);
  }
  const bytes = (value.length - 2) / 2;
  if ((exactBytes !== undefined && bytes !== exactBytes) || bytes < minBytes) {
    fail('INVALID_CALLDATA', `${label} has an invalid byte length.`);
  }
  return value.toLowerCase();
}

function normalizeAction(value) {
  strictObject(value, ACTION_KEYS, 'action');
  if (typeof value.selector !== 'string') fail('INVALID_ACTION', 'The action selector is invalid.');
  const selector = value.selector.toLowerCase();
  if (selector !== TRANSFER_FROM_SELECTOR && selector !== TRANSFER_FROM_ACTION) {
    fail('INVALID_ACTION', 'Only the transferFrom action is permitted.');
  }
  if (value.supported !== true || value.hasAmount !== true || value.amountIndex !== TRANSFER_FROM_AMOUNT_INDEX) {
    fail('INVALID_ACTION', 'transferFrom must use supported=true, hasAmount=true and amountIndex=2.');
  }
  return Object.freeze({
    selector: TRANSFER_FROM_ACTION,
    supported: true,
    hasAmount: true,
    amountIndex: TRANSFER_FROM_AMOUNT_INDEX
  });
}

function normalizePolicy(value) {
  strictObject(value, POLICY_KEYS, 'policy');
  const chainId = normalizeUint(value.chainId, 'chainId').toString();
  if (chainId !== SEPOLIA_CHAIN_ID) fail('WRONG_CHAIN', 'RAMS execution is restricted to Ethereum Sepolia.');
  const principal = normalizeAddress(value.principal, 'principal');
  const agent = normalizeAddress(value.agent, 'agent');
  const executor = normalizeAddress(value.executor, 'executor');
  const token = normalizeAddress(value.token, 'token');
  const recipient = normalizeAddress(value.recipient, 'recipient');
  if (principal !== KNOWN_PRINCIPAL || agent !== KNOWN_AGENT) {
    fail('WRONG_IDENTITY', 'The policy must bind the known principal and agent.');
  }
  if (executor === PLATFORM_DEFAULT_EXECUTOR) {
    fail('DEFAULT_EXECUTOR', 'The Brickken platform default executor is not the principal\'s dedicated executor.');
  }
  if (new Set([principal, agent, executor, token, recipient]).size !== 5) {
    fail('ADDRESS_COLLISION', 'Principal, agent, executor, token and recipient must be distinct.');
  }
  const maxTransactionValue = normalizeUint(value.maxTransactionValue, 'maxTransactionValue', { positive: true });
  const maxCumulativeValue = normalizeUint(value.maxCumulativeValue, 'maxCumulativeValue', { positive: true });
  const cumulativeUsed = normalizeUint(value.cumulativeUsed, 'cumulativeUsed');
  const allowance = normalizeUint(value.allowance, 'allowance');
  if (maxTransactionValue > maxCumulativeValue || cumulativeUsed > maxCumulativeValue) {
    fail('INVALID_CAPS', 'The mandate caps and cumulative usage are inconsistent.');
  }
  return Object.freeze({
    chainId,
    principal,
    agent,
    executor,
    token,
    recipient,
    action: normalizeAction(value.action),
    maxTransactionValue: maxTransactionValue.toString(),
    maxCumulativeValue: maxCumulativeValue.toString(),
    cumulativeUsed: cumulativeUsed.toString(),
    allowance: allowance.toString()
  });
}

function normalizeTransfer(value, policy) {
  strictObject(value, TRANSFER_KEYS, 'transfer');
  const from = normalizeAddress(value.from, 'transfer.from');
  const to = normalizeAddress(value.to, 'transfer.to');
  const amount = normalizeUint(value.amount, 'transfer.amount', { positive: true });
  if (from !== policy.principal || to !== policy.recipient) {
    fail('TRANSFER_MISMATCH', 'The transfer must use the policy principal and recipient.');
  }
  if (amount > BigInt(policy.maxTransactionValue)) fail('TRANSACTION_CAP', 'The amount exceeds the per-transaction cap.');
  if (BigInt(policy.cumulativeUsed) + amount > BigInt(policy.maxCumulativeValue)) {
    fail('CUMULATIVE_CAP', 'The amount exceeds the remaining cumulative cap.');
  }
  if (amount > BigInt(policy.allowance)) fail('ALLOWANCE', 'The amount exceeds the executor token allowance.');
  return Object.freeze({ from, to, amount: amount.toString() });
}

function canonicalValue(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail('INVALID_CANONICAL_VALUE', 'Canonical numbers must be safe integers.');
    return value;
  }
  if (Array.isArray(value)) {
    if (value.some(item => item === undefined) || Object.keys(value).length !== value.length) {
      fail('INVALID_CANONICAL_VALUE', 'Canonical arrays cannot contain missing or undefined values.');
    }
    return value.map(canonicalValue);
  }
  if (value && typeof value === 'object' &&
      (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
    const result = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      if (value[key] === undefined) fail('INVALID_CANONICAL_VALUE', 'Undefined values cannot be hashed.');
      result[key] = canonicalValue(value[key]);
    }
    return result;
  }
  fail('INVALID_CANONICAL_VALUE', 'Only JSON-compatible values can be hashed.');
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function sha256Canonical(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function encodeAddressWord(value, label) {
  return '0'.repeat(24) + normalizeAddress(value, label).slice(2);
}

export function encodeTransferFrom(value) {
  strictObject(value, TRANSFER_KEYS, 'transferFrom');
  const rawAmount = normalizeUint(value.amount, 'amount');
  return TRANSFER_FROM_SELECTOR +
    encodeAddressWord(value.from, 'from') +
    encodeAddressWord(value.to, 'to') +
    rawAmount.toString(16).padStart(64, '0');
}

export function decodeTransferFrom(calldata) {
  const data = normalizeHex(calldata, 'transferFrom calldata', { exactBytes: 100 });
  if (data.slice(0, 10) !== TRANSFER_FROM_SELECTOR) fail('INVALID_SELECTOR', 'Calldata is not transferFrom.');
  const words = [data.slice(10, 74), data.slice(74, 138), data.slice(138, 202)];
  if (!words[0].startsWith('0'.repeat(24)) || !words[1].startsWith('0'.repeat(24))) {
    fail('INVALID_PADDING', 'Address words must have exact leading-zero ABI padding.');
  }
  return Object.freeze({
    from: normalizeAddress('0x' + words[0].slice(24), 'from'),
    to: normalizeAddress('0x' + words[1].slice(24), 'to'),
    amount: BigInt('0x' + words[2]).toString()
  });
}

const INTENT_SCOPE = Object.freeze({
  offlineOnly: true,
  chainWriteAuthorized: false,
  outerEncoderAvailable: false,
  executorBindingVerified: false
});

function intentPayload(policy, transfer) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'rams-transferFrom-intent',
    policy,
    transfer,
    innerCalldata: encodeTransferFrom(transfer),
    scope: INTENT_SCOPE
  });
}

export function createTransferFromIntent(policyInput, transferInput) {
  const policy = normalizePolicy(policyInput);
  const transfer = normalizeTransfer(transferInput, policy);
  const payload = intentPayload(policy, transfer);
  return Object.freeze({
    ...payload,
    policyHash: sha256Canonical(policy),
    intentHash: sha256Canonical(payload)
  });
}

export const buildTransferFromIntent = createTransferFromIntent;

export function validateTransferFromIntent(value) {
  strictObject(value, INTENT_KEYS, 'intent');
  strictObject(value.scope, INTENT_SCOPE_KEYS, 'intent scope');
  const rebuilt = createTransferFromIntent(value.policy, value.transfer);
  if (canonicalJson(value) !== canonicalJson(rebuilt)) {
    fail('INTENT_INTEGRITY', 'The transfer intent or its canonical hashes changed.');
  }
  return rebuilt;
}

function normalizeTransaction(value, label = 'transaction') {
  strictObject(value, TRANSACTION_KEYS, label);
  const chainId = normalizeUint(value.chainId, `${label}.chainId`).toString();
  const from = normalizeAddress(value.from, `${label}.from`);
  const to = normalizeAddress(value.to, `${label}.to`);
  const transactionValue = normalizeUint(value.value, `${label}.value`);
  const data = normalizeHex(value.data, `${label}.data`, { minBytes: 4 });
  const nonce = normalizeUint(value.nonce, `${label}.nonce`);
  const gasLimit = normalizeUint(value.gasLimit, `${label}.gasLimit`, { positive: true });
  const maxPriorityFeePerGas = normalizeUint(value.maxPriorityFeePerGas, `${label}.maxPriorityFeePerGas`);
  const maxFeePerGas = normalizeUint(value.maxFeePerGas, `${label}.maxFeePerGas`);
  if (value.type !== 2) fail('INVALID_TRANSACTION', 'Only an exact EIP-1559 type 2 transaction is permitted.');
  if (maxPriorityFeePerGas > maxFeePerGas) fail('INVALID_FEES', 'The priority fee exceeds the maximum fee.');
  return Object.freeze({
    chainId,
    from,
    to,
    value: transactionValue.toString(),
    data,
    nonce: nonce.toString(),
    gasLimit: gasLimit.toString(),
    type: 2,
    maxPriorityFeePerGas: maxPriorityFeePerGas.toString(),
    maxFeePerGas: maxFeePerGas.toString()
  });
}

const EXPECTED_SCOPE = Object.freeze({
  offlineOnly: true,
  chainWriteAuthorized: false,
  outerEncoderAvailable: false,
  outerCalldataVerified: false,
  signingReady: false
});

export function buildExpectedUnsignedTransaction(intentInput, binding) {
  const intent = validateTransferFromIntent(intentInput);
  strictObject(binding, BINDING_KEYS, 'transaction binding');
  const transaction = normalizeTransaction({
    chainId: intent.policy.chainId,
    from: intent.policy.agent,
    to: intent.policy.executor,
    value: '0',
    data: binding.outerCalldata,
    nonce: binding.nonce,
    gasLimit: binding.gasLimit,
    type: binding.type,
    maxPriorityFeePerGas: binding.maxPriorityFeePerGas,
    maxFeePerGas: binding.maxFeePerGas
  }, 'expected transaction');
  const payload = Object.freeze({
    schemaVersion: 1,
    kind: 'rams-unsigned-transaction-intent',
    intent,
    transaction,
    scope: EXPECTED_SCOPE
  });
  return Object.freeze({ ...payload, transactionIntentHash: sha256Canonical(payload) });
}

function validateExpected(value) {
  strictObject(value, EXPECTED_KEYS, 'expected transaction intent');
  strictObject(value.scope, EXPECTED_SCOPE_KEYS, 'expected transaction scope');
  const intent = validateTransferFromIntent(value.intent);
  const rebuilt = buildExpectedUnsignedTransaction(intent, {
    outerCalldata: value.transaction.data,
    nonce: value.transaction.nonce,
    gasLimit: value.transaction.gasLimit,
    type: value.transaction.type,
    maxPriorityFeePerGas: value.transaction.maxPriorityFeePerGas,
    maxFeePerGas: value.transaction.maxFeePerGas
  });
  if (canonicalJson(value) !== canonicalJson(rebuilt)) {
    fail('TRANSACTION_INTENT_INTEGRITY', 'The expected unsigned transaction intent changed.');
  }
  return rebuilt;
}

export function validatePreparedTransactions(transactions, expectedInput, ceilingInput) {
  if (!Array.isArray(transactions) || transactions.length !== 1) {
    fail('BATCH_REJECTED', 'Exactly one prepared transaction is permitted.');
  }
  const expected = validateExpected(expectedInput);
  const actual = normalizeTransaction(transactions[0], 'prepared transaction');
  if (ceilingInput === undefined) {
    if (canonicalJson(actual) !== canonicalJson(expected.transaction)) {
      fail('PREPARED_TRANSACTION_MISMATCH', 'The prepared transaction does not match the complete expected intent.');
    }
  } else {
    strictObject(ceilingInput, PREPARED_TRANSACTION_CEILING_KEYS, 'prepared transaction ceilings');
    const ceilings = Object.freeze({
      gasLimit: normalizeUint(ceilingInput.gasLimit, 'ceilings.gasLimit', { positive: true }).toString(),
      maxPriorityFeePerGas: normalizeUint(ceilingInput.maxPriorityFeePerGas, 'ceilings.maxPriorityFeePerGas', { positive: true }).toString(),
      maxFeePerGas: normalizeUint(ceilingInput.maxFeePerGas, 'ceilings.maxFeePerGas', { positive: true }).toString()
    });
    if (PREPARED_TRANSACTION_CEILING_KEYS.some(key => expected.transaction[key] !== ceilings[key])) {
      fail('TRANSACTION_CEILING_INTEGRITY', 'The supplied ceilings do not match the reviewed transaction intent.');
    }
    if (EXACT_PREPARED_TRANSACTION_KEYS.some(key => actual[key] !== expected.transaction[key])) {
      fail('PREPARED_TRANSACTION_MISMATCH', 'The prepared transaction does not match the exact intent fields.');
    }
    if (PREPARED_TRANSACTION_CEILING_KEYS.some(key => BigInt(actual[key]) > BigInt(ceilings[key]))) {
      fail('PREPARED_TRANSACTION_CEILING', 'The prepared transaction exceeds a reviewed gas or fee ceiling.');
    }
  }
  return Object.freeze({
    valid: true,
    transaction: actual,
    intentHash: expected.intent.intentHash,
    transactionIntentHash: expected.transactionIntentHash,
    offlineOnly: true,
    outerCalldataVerified: false,
    signingReady: false
  });
}
