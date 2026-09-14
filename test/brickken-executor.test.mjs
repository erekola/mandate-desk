import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  KNOWN_AGENT,
  KNOWN_PRINCIPAL,
  TRANSFER_FROM_SELECTOR,
  createTransferFromIntent,
  sha256Canonical
} from '../src/brickken-intent.mjs';
import {
  EXECUTE_SELECTOR,
  PROVISIONED_EXECUTOR,
  SET_ACTION_SELECTOR,
  buildOfflineActionSetupCall,
  buildOfflineExecutionCall,
  decodeExecutorExecute,
  decodeSetActionTransferFrom,
  encodeExecutorExecute,
  encodeSetActionTransferFrom,
  validateOfflineActionSetupCall,
  validateOfflineExecutionCall
} from '../src/brickken-executor.mjs';

const TOKEN = '0x5555555555555555555555555555555555555555';
const RECIPIENT = '0x6666666666666666666666666666666666666666';
const OTHER = '0x7777777777777777777777777777777777777777';
const wordAddress = value => '0'.repeat(24) + value.slice(2).toLowerCase();
const wordUint = value => BigInt(value).toString(16).padStart(64, '0');
// Exact 132-byte public eth_call vector preserved in
// verification/brickken-sandbox-2026-09-14/public-chain/action-setup-simulation.json.
const SET_ACTION_VECTOR = '0xa4a2285423b872dd00000000000000000000000000000000000000000000000000000000' +
  '0000000000000000000000000000000000000000000000000000000000000001' +
  '0000000000000000000000000000000000000000000000000000000000000001' +
  '0000000000000000000000000000000000000000000000000000000000000002';
const PUBLIC_SIMULATION = JSON.parse(fs.readFileSync(new URL(
  '../verification/brickken-sandbox-2026-09-14/public-chain/action-setup-simulation.json', import.meta.url
), 'utf8'));

function intent(extraPolicy = {}, extraTransfer = {}) {
  const policy = {
    chainId: '11155111', principal: KNOWN_PRINCIPAL, agent: KNOWN_AGENT,
    executor: PROVISIONED_EXECUTOR, token: TOKEN, recipient: RECIPIENT,
    action: { selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: true, amountIndex: 2 },
    maxTransactionValue: '100', maxCumulativeValue: '200', cumulativeUsed: '20', allowance: '90',
    ...extraPolicy
  };
  return createTransferFromIntent(policy, {
    from: KNOWN_PRINCIPAL, to: RECIPIENT, amount: '80', ...extraTransfer
  });
}

function executionVector() {
  const inner = TRANSFER_FROM_SELECTOR + wordAddress(KNOWN_PRINCIPAL) + wordAddress(RECIPIENT) + wordUint(80);
  return EXECUTE_SELECTOR + wordAddress(TOKEN) + wordUint(64) + wordUint(100) + inner.slice(2) + '0'.repeat(56);
}

function replaceHex(value, start, length, replacement) {
  return value.slice(0, start) + replacement + value.slice(start + length);
}

test('setAction encoder matches the independent fixed ABI word vector', () => {
  assert.equal(SET_ACTION_SELECTOR, '0xa4a22854');
  assert.equal(EXECUTE_SELECTOR, '0x1cff79cd');
  assert.equal(PROVISIONED_EXECUTOR, '0xff666ccd01541cd7abcabb70dba1cffec8c01d9b');
  assert.equal(PUBLIC_SIMULATION.calldata, SET_ACTION_VECTOR);
  assert.equal(PUBLIC_SIMULATION.calldataBytes, 132);
  assert.equal(PUBLIC_SIMULATION.ownerSimulation.success, true);
  const data = encodeSetActionTransferFrom();
  assert.equal(data, SET_ACTION_VECTOR);
  assert.equal(data.length, 2 + 132 * 2);
  assert.deepEqual(decodeSetActionTransferFrom(data), {
    executor: PROVISIONED_EXECUTOR,
    owner: KNOWN_PRINCIPAL,
    selector: TRANSFER_FROM_SELECTOR,
    supported: true,
    hasAmount: true,
    amountIndex: 2
  });
});

test('setAction decoder rejects missing, extra, selector, bytes4 padding and every fixed argument mutation', () => {
  for (const bad of [
    SET_ACTION_VECTOR.slice(0, -2),
    SET_ACTION_VECTOR + '00',
    '0xdeadbeef' + SET_ACTION_VECTOR.slice(10),
    replaceHex(SET_ACTION_VECTOR, 18, 2, '01'),
    replaceHex(SET_ACTION_VECTOR, 10 + 64, 64, '0'.repeat(64)),
    replaceHex(SET_ACTION_VECTOR, 10 + 128, 64, '0'.repeat(64)),
    replaceHex(SET_ACTION_VECTOR, 10 + 192, 64, wordUint(1))
  ]) assert.throws(() => decodeSetActionTransferFrom(bad));
});

test('execute encoder matches an independent address, offset, length, data and tail vector', () => {
  const value = intent();
  const expected = executionVector(value);
  const data = encodeExecutorExecute(value);
  assert.equal(data, expected);
  assert.equal(data.length, 2 + 228 * 2);
  assert.deepEqual(decodeExecutorExecute(data, value), {
    target: TOKEN,
    innerCalldata: value.innerCalldata,
    transfer: value.transfer
  });
});

test('execute decoder rejects exact ABI framing mutations', () => {
  const value = intent();
  const data = executionVector(value);
  for (const bad of [
    data.slice(0, -2),
    data + '00',
    '0xdeadbeef' + data.slice(10),
    replaceHex(data, 10, 2, '01'),
    replaceHex(data, 10 + 64, 64, wordUint(32)),
    replaceHex(data, 10 + 128, 64, wordUint(99)),
    replaceHex(data, 10 + 192, 8, 'deadbeef'),
    replaceHex(data, data.length - 2, 2, '01')
  ]) assert.throws(() => decodeExecutorExecute(bad, value));
});

test('execute decoder binds target, from, recipient and amount to the validated intent', () => {
  const value = intent();
  const data = executionVector(value);
  const mutations = [
    replaceHex(data, 10 + 24, 40, OTHER.slice(2)),
    replaceHex(data, 10 + 192 + 8 + 24, 40, OTHER.slice(2)),
    replaceHex(data, 10 + 192 + 8 + 64 + 24, 40, OTHER.slice(2)),
    replaceHex(data, 10 + 192 + 8 + 128, 64, wordUint(79))
  ];
  for (const bad of mutations) assert.throws(() => decodeExecutorExecute(bad, value), { code: 'EXECUTION_MISMATCH' });
});

test('executor codecs reject an otherwise valid intent for another executor', () => {
  const value = intent({ executor: OTHER });
  assert.throws(() => encodeExecutorExecute(value), { code: 'WRONG_EXECUTOR' });
  assert.throws(() => decodeExecutorExecute(executionVector(), value), { code: 'WRONG_EXECUTOR' });
});

test('offline action setup call fixes owner, executor, chain, zero value and false readiness claims', () => {
  const setup = buildOfflineActionSetupCall();
  assert.equal(setup.call.from, KNOWN_PRINCIPAL);
  assert.equal(setup.call.to, PROVISIONED_EXECUTOR);
  assert.equal(setup.call.chainId, '11155111');
  assert.equal(setup.call.value, '0');
  assert.equal(setup.call.data, SET_ACTION_VECTOR);
  assert.equal(setup.scope.chainWriteAuthorized, false);
  assert.equal(setup.scope.signingReady, false);
  assert.equal(setup.scope.provisioningReady, false);
  assert.equal(setup.outerCalldataHash.length, 64);
  assert.equal(setup.callHash.length, 64);
  assert.deepEqual(validateOfflineActionSetupCall(setup), setup);
});

test('offline action setup validator rejects field, calldata, hash and unknown-field tampering', () => {
  const original = buildOfflineActionSetupCall();
  for (const mutate of [
    value => { value.call.from = KNOWN_AGENT; },
    value => { value.call.to = OTHER; },
    value => { value.call.chainId = '1'; },
    value => { value.call.value = '1'; },
    value => { value.call.data = value.call.data.slice(0, -2) + '01'; },
    value => { value.outerCalldataHash = '0'.repeat(64); },
    value => { value.callHash = '0'.repeat(64); },
    value => { value.authorize = true; },
    value => { value.call.nonce = 1; },
    value => { value.call.gasLimit = '21000'; },
    value => { delete value.call.chainId; }
  ]) {
    const changed = structuredClone(original); mutate(changed);
    assert.throws(() => validateOfflineActionSetupCall(changed));
  }
  for (const field of ['chainWriteAuthorized', 'signingReady', 'provisioningReady']) {
    const changed = structuredClone(original);
    changed.scope[field] = true;
    const { callHash: ignored, ...payload } = changed;
    changed.callHash = sha256Canonical(payload);
    assert.throws(() => validateOfflineActionSetupCall(changed));
  }
});

test('offline execution call binds the complete intent, semantic calldata and exact call fields', () => {
  const value = intent();
  const execution = buildOfflineExecutionCall(value);
  assert.equal(execution.call.from, KNOWN_AGENT);
  assert.equal(execution.call.to, PROVISIONED_EXECUTOR);
  assert.equal(execution.call.chainId, '11155111');
  assert.equal(execution.call.value, '0');
  assert.equal(execution.call.data, executionVector(value));
  assert.equal(execution.scope.chainWriteAuthorized, false);
  assert.equal(execution.scope.signingReady, false);
  assert.equal(execution.scope.provisioningReady, false);
  assert.deepEqual(validateOfflineExecutionCall(execution), execution);
});

test('offline execution validator rejects intent, call, calldata, hashes and unknown fields', () => {
  const original = buildOfflineExecutionCall(intent());
  for (const mutate of [
    value => { value.intent.transfer.amount = '79'; },
    value => { value.call.from = KNOWN_PRINCIPAL; },
    value => { value.call.to = OTHER; },
    value => { value.call.chainId = '1'; },
    value => { value.call.value = '1'; },
    value => { value.call.data = replaceHex(value.call.data, 10 + 24, 40, OTHER.slice(2)); },
    value => { value.outerCalldataHash = '0'.repeat(64); },
    value => { value.callHash = '0'.repeat(64); },
    value => { value.nonce = 1; },
    value => { value.call.nonce = 1; },
    value => { value.call.gasLimit = '21000'; },
    value => { delete value.call.value; }
  ]) {
    const changed = structuredClone(original); mutate(changed);
    assert.throws(() => validateOfflineExecutionCall(changed));
  }
  for (const field of ['chainWriteAuthorized', 'signingReady', 'provisioningReady']) {
    const changed = structuredClone(original);
    changed.scope[field] = true;
    const { callHash: ignored, ...payload } = changed;
    changed.callHash = sha256Canonical(payload);
    assert.throws(() => validateOfflineExecutionCall(changed));
  }
});
