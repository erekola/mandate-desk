import {
  KNOWN_AGENT,
  KNOWN_PRINCIPAL,
  SEPOLIA_CHAIN_ID,
  TRANSFER_FROM_ACTION,
  TRANSFER_FROM_AMOUNT_INDEX,
  TRANSFER_FROM_SELECTOR,
  canonicalJson,
  decodeTransferFrom,
  encodeTransferFrom,
  sha256Canonical,
  validateTransferFromIntent
} from './brickken-intent.mjs';

export const PROVISIONED_EXECUTOR = '0xff666ccd01541cd7abcabb70dba1cffec8c01d9b';
export const SET_ACTION_SELECTOR = '0xa4a22854';
export const EXECUTE_SELECTOR = '0x1cff79cd';

const WORD_HEX = 64;
const TRANSFER_FROM_BYTES = 100;
const EXECUTE_BYTES = 228;
const SET_ACTION_BYTES = 132;
const ONE_WORD = '0'.repeat(63) + '1';
const TWO_WORD = '0'.repeat(63) + '2';
const OFFSET_WORD = '0'.repeat(62) + '40';
const LENGTH_WORD = '0'.repeat(62) + '64';
const EXECUTE_PADDING = '0'.repeat(56);
const CALL_KEYS = ['chainId', 'from', 'to', 'value', 'data'];
const SCOPE_KEYS = ['offlineOnly', 'chainWriteAuthorized', 'signingReady', 'provisioningReady', 'abiSemanticsValidated'];
const EXECUTION_KEYS = ['schemaVersion', 'kind', 'intent', 'call', 'scope', 'outerCalldataHash', 'callHash'];
const SETUP_KEYS = ['schemaVersion', 'kind', 'configuration', 'call', 'scope', 'outerCalldataHash', 'callHash'];
const CONFIG_KEYS = ['executor', 'owner', 'selector', 'supported', 'hasAmount', 'amountIndex'];

export class BrickkenExecutorError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrickkenExecutorError';
    this.code = code;
  }
}

function fail(code, message) { throw new BrickkenExecutorError(code, message); }

function strictObject(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
      Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key)) ||
      Object.keys(value).some(key => !keys.includes(key))) {
    fail('INVALID_STRUCTURE', `${label} fields do not match the allowed structure.`);
  }
}

function calldata(value, bytes, label) {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(value) || (value.length - 2) / 2 !== bytes) {
    fail('INVALID_CALLDATA', `${label} must have the exact ABI byte length.`);
  }
  return value.toLowerCase();
}

function address(value, label) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value) || /^0x0{40}$/i.test(value)) {
    fail('INVALID_ADDRESS', `${label} must be a nonzero Ethereum address.`);
  }
  return value.toLowerCase();
}

function addressWord(value) { return '0'.repeat(24) + address(value, 'address').slice(2); }

function decodeAddressWord(word, label) {
  if (word.length !== WORD_HEX || !/^0{24}[0-9a-f]{40}$/.test(word)) {
    fail('INVALID_PADDING', `${label} has invalid ABI address padding.`);
  }
  return address('0x' + word.slice(24), label);
}

function validatedIntent(value) {
  let intent;
  try { intent = validateTransferFromIntent(value); }
  catch { fail('INVALID_INTENT', 'A complete valid transferFrom intent is required.'); }
  if (intent.policy.executor !== PROVISIONED_EXECUTOR) {
    fail('WRONG_EXECUTOR', 'The intent must use the provisioned principal-bound executor.');
  }
  return intent;
}

const OFFLINE_SCOPE = Object.freeze({
  offlineOnly: true,
  chainWriteAuthorized: false,
  signingReady: false,
  provisioningReady: false,
  abiSemanticsValidated: true
});

const ACTION_CONFIGURATION = Object.freeze({
  executor: PROVISIONED_EXECUTOR,
  owner: KNOWN_PRINCIPAL,
  selector: TRANSFER_FROM_SELECTOR,
  supported: true,
  hasAmount: true,
  amountIndex: TRANSFER_FROM_AMOUNT_INDEX
});

export function encodeSetActionTransferFrom() {
  return SET_ACTION_SELECTOR + TRANSFER_FROM_SELECTOR.slice(2) + '0'.repeat(56) + ONE_WORD + ONE_WORD + TWO_WORD;
}

export function decodeSetActionTransferFrom(value) {
  const data = calldata(value, SET_ACTION_BYTES, 'setAction calldata');
  if (data.slice(0, 10) !== SET_ACTION_SELECTOR) fail('INVALID_SELECTOR', 'Calldata is not setAction.');
  const words = [data.slice(10, 74), data.slice(74, 138), data.slice(138, 202), data.slice(202, 266)];
  if (words[0] !== TRANSFER_FROM_ACTION.slice(2)) fail('INVALID_ACTION', 'setAction must configure transferFrom.');
  if (words[1] !== ONE_WORD || words[2] !== ONE_WORD || words[3] !== TWO_WORD) {
    fail('INVALID_ACTION', 'setAction must configure supported=true, hasAmount=true and amountIndex=2.');
  }
  return ACTION_CONFIGURATION;
}

export function encodeExecutorExecute(intentInput) {
  const intent = validatedIntent(intentInput);
  const inner = encodeTransferFrom(intent.transfer);
  return EXECUTE_SELECTOR + addressWord(intent.policy.token) + OFFSET_WORD + LENGTH_WORD + inner.slice(2) + EXECUTE_PADDING;
}

export function decodeExecutorExecute(value, intentInput) {
  const intent = validatedIntent(intentInput);
  const data = calldata(value, EXECUTE_BYTES, 'execute calldata');
  if (data.slice(0, 10) !== EXECUTE_SELECTOR) fail('INVALID_SELECTOR', 'Calldata is not execute(address,bytes).');
  const target = decodeAddressWord(data.slice(10, 74), 'execute target');
  if (data.slice(74, 138) !== OFFSET_WORD) fail('INVALID_OFFSET', 'The execute bytes offset must be 64.');
  if (data.slice(138, 202) !== LENGTH_WORD) fail('INVALID_LENGTH', 'The execute inner calldata length must be 100 bytes.');
  const innerCalldata = '0x' + data.slice(202, 402);
  if (data.slice(402) !== EXECUTE_PADDING) fail('INVALID_PADDING', 'The execute bytes tail must contain 28 zero bytes.');
  let transfer;
  try { transfer = decodeTransferFrom(innerCalldata); }
  catch { fail('INVALID_INNER_CALLDATA', 'The execute payload must contain exact transferFrom calldata.'); }
  if (target !== intent.policy.token || innerCalldata !== intent.innerCalldata ||
      transfer.from !== intent.policy.principal || transfer.to !== intent.policy.recipient ||
      transfer.amount !== intent.transfer.amount) {
    fail('EXECUTION_MISMATCH', 'The execute target or transfer fields do not match the intent.');
  }
  return Object.freeze({ target, innerCalldata, transfer });
}

function fixedCall(from, data) {
  return Object.freeze({
    chainId: SEPOLIA_CHAIN_ID,
    from,
    to: PROVISIONED_EXECUTOR,
    value: '0',
    data
  });
}

function validateCallShape(value, expectedFrom, expectedData) {
  strictObject(value, CALL_KEYS, 'call');
  if (value.chainId !== SEPOLIA_CHAIN_ID || value.from !== expectedFrom ||
      value.to !== PROVISIONED_EXECUTOR || value.value !== '0' || value.data !== expectedData) {
    fail('CALL_MISMATCH', 'The offline call does not match the exact expected transaction fields.');
  }
}

export function buildOfflineActionSetupCall() {
  const call = fixedCall(KNOWN_PRINCIPAL, encodeSetActionTransferFrom());
  const payload = Object.freeze({
    schemaVersion: 1,
    kind: 'rams-offline-action-setup-call',
    configuration: ACTION_CONFIGURATION,
    call,
    scope: OFFLINE_SCOPE,
    outerCalldataHash: sha256Canonical(call.data)
  });
  return Object.freeze({ ...payload, callHash: sha256Canonical(payload) });
}

export function validateOfflineActionSetupCall(value) {
  strictObject(value, SETUP_KEYS, 'action setup call');
  strictObject(value.configuration, CONFIG_KEYS, 'action setup configuration');
  strictObject(value.scope, SCOPE_KEYS, 'action setup scope');
  const expectedData = encodeSetActionTransferFrom();
  validateCallShape(value.call, KNOWN_PRINCIPAL, expectedData);
  decodeSetActionTransferFrom(value.call.data);
  const rebuilt = buildOfflineActionSetupCall();
  if (canonicalJson(value) !== canonicalJson(rebuilt)) fail('CALL_INTEGRITY', 'The action setup call or hash changed.');
  return rebuilt;
}

export function buildOfflineExecutionCall(intentInput) {
  const intent = validatedIntent(intentInput);
  const data = encodeExecutorExecute(intent);
  decodeExecutorExecute(data, intent);
  const call = fixedCall(KNOWN_AGENT, data);
  const payload = Object.freeze({
    schemaVersion: 1,
    kind: 'rams-offline-execution-call',
    intent,
    call,
    scope: OFFLINE_SCOPE,
    outerCalldataHash: sha256Canonical(call.data)
  });
  return Object.freeze({ ...payload, callHash: sha256Canonical(payload) });
}

export function validateOfflineExecutionCall(value) {
  strictObject(value, EXECUTION_KEYS, 'execution call');
  strictObject(value.scope, SCOPE_KEYS, 'execution scope');
  const intent = validatedIntent(value.intent);
  const expectedData = encodeExecutorExecute(intent);
  decodeExecutorExecute(value.call?.data, intent);
  validateCallShape(value.call, KNOWN_AGENT, expectedData);
  const rebuilt = buildOfflineExecutionCall(intent);
  if (canonicalJson(value) !== canonicalJson(rebuilt)) fail('CALL_INTEGRITY', 'The execution call or hash changed.');
  return rebuilt;
}
