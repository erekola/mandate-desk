import test from 'node:test';
import assert from 'node:assert/strict';
import {
  KNOWN_AGENT,
  KNOWN_PRINCIPAL,
  PLATFORM_DEFAULT_EXECUTOR,
  SEPOLIA_CHAIN_ID,
  TRANSFER_FROM_ACTION,
  TRANSFER_FROM_SELECTOR,
  buildExpectedUnsignedTransaction,
  canonicalJson,
  createTransferFromIntent,
  decodeTransferFrom,
  encodeTransferFrom,
  sha256Canonical,
  validatePreparedTransactions,
  validateTransferFromIntent
} from '../src/brickken-intent.mjs';

const EXECUTOR = '0x4444444444444444444444444444444444444444';
const TOKEN = '0x5555555555555555555555555555555555555555';
const RECIPIENT = '0x6666666666666666666666666666666666666666';
const OTHER = '0x7777777777777777777777777777777777777777';
const OUTER_CALLDATA = '0xabcdef01' + '12'.repeat(128);

function policy(extra = {}) {
  return {
    chainId: SEPOLIA_CHAIN_ID,
    principal: KNOWN_PRINCIPAL,
    agent: KNOWN_AGENT,
    executor: EXECUTOR,
    token: TOKEN,
    recipient: RECIPIENT,
    action: { selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: true, amountIndex: 2 },
    maxTransactionValue: '100',
    maxCumulativeValue: '200',
    cumulativeUsed: '20',
    allowance: '90',
    ...extra
  };
}

function transfer(extra = {}) {
  return { from: KNOWN_PRINCIPAL, to: RECIPIENT, amount: '80', ...extra };
}

function intent(policyExtra = {}, transferExtra = {}) {
  return createTransferFromIntent(policy(policyExtra), transfer(transferExtra));
}

function expected(intentValue = intent(), extra = {}) {
  return buildExpectedUnsignedTransaction(intentValue, {
    outerCalldata: OUTER_CALLDATA,
    nonce: 7,
    gasLimit: '0x5208',
    type: 2,
    maxPriorityFeePerGas: '1000000',
    maxFeePerGas: '2000000',
    ...extra
  });
}

function prepared(expectedValue = expected()) {
  return [structuredClone(expectedValue.transaction)];
}

test('transferFrom encoding is exact and decodes addresses and an arbitrary uint256', () => {
  const amount = (1n << 255n) + 123n;
  const calldata = encodeTransferFrom({ from: KNOWN_PRINCIPAL, to: RECIPIENT, amount });
  assert.equal(calldata.length, 202);
  assert.equal(calldata.slice(0, 10), TRANSFER_FROM_SELECTOR);
  assert.equal(calldata.slice(10, 34), '0'.repeat(24));
  assert.equal(calldata.slice(74, 98), '0'.repeat(24));
  assert.deepEqual(decodeTransferFrom(calldata), {
    from: KNOWN_PRINCIPAL,
    to: RECIPIENT,
    amount: amount.toString()
  });
});

test('decoder rejects selector, length, trailing bytes and nonzero address padding', () => {
  const data = encodeTransferFrom(transfer());
  assert.throws(() => decodeTransferFrom('0xdeadbeef' + data.slice(10)), { code: 'INVALID_SELECTOR' });
  assert.throws(() => decodeTransferFrom(data.slice(0, -2)), { code: 'INVALID_CALLDATA' });
  assert.throws(() => decodeTransferFrom(data + '00'), { code: 'INVALID_CALLDATA' });
  assert.throws(() => decodeTransferFrom(data.slice(0, 10) + '01' + data.slice(12)), { code: 'INVALID_PADDING' });
});

test('canonical policy and full intent hashes are deterministic and cover normalized content', () => {
  const first = intent();
  const reordered = createTransferFromIntent({
    allowance: '0x5a', cumulativeUsed: 20n, maxCumulativeValue: 200,
    maxTransactionValue: 100, action: { amountIndex: 2, hasAmount: true, supported: true, selector: TRANSFER_FROM_ACTION },
    recipient: RECIPIENT.toUpperCase().replace('0X', '0x'), token: TOKEN,
    executor: EXECUTOR, agent: KNOWN_AGENT, principal: KNOWN_PRINCIPAL,
    chainId: '0xaa36a7'
  }, { amount: 80n, to: RECIPIENT, from: KNOWN_PRINCIPAL });
  assert.equal(first.policyHash, reordered.policyHash);
  assert.equal(first.intentHash, reordered.intentHash);
  assert.match(first.policyHash, /^[a-f0-9]{64}$/);
  assert.equal(first.policyHash, sha256Canonical(first.policy));
  assert.equal(canonicalJson({ z: 1, a: 2 }), '{"a":2,"z":1}');
  const prototypeKey = Object.create(null);
  prototypeKey.safe = 1;
  prototypeKey.__proto__ = 'preserved-data-key';
  assert.equal(canonicalJson(prototypeKey), '{"__proto__":"preserved-data-key","safe":1}');
  assert.deepEqual(decodeTransferFrom(first.innerCalldata), first.transfer);
  assert.equal(first.scope.chainWriteAuthorized, false);
});

test('policy binds Sepolia, the known identities, dedicated executor, token and recipient', () => {
  assert.throws(() => intent({ chainId: '1' }), { code: 'WRONG_CHAIN' });
  assert.throws(() => intent({ principal: OTHER }), { code: 'WRONG_IDENTITY' });
  assert.throws(() => intent({ agent: OTHER }), { code: 'WRONG_IDENTITY' });
  assert.throws(() => intent({ executor: PLATFORM_DEFAULT_EXECUTOR }), { code: 'DEFAULT_EXECUTOR' });
  assert.throws(() => intent({ token: '0x' + '0'.repeat(40) }), { code: 'INVALID_ADDRESS' });
  assert.throws(() => intent({ recipient: '0x' + '0'.repeat(40) }), { code: 'INVALID_ADDRESS' });
  assert.throws(() => intent({ recipient: TOKEN }, { to: TOKEN }), { code: 'ADDRESS_COLLISION' });
  assert.throws(() => intent({ executor: TOKEN }), { code: 'ADDRESS_COLLISION' });
  assert.throws(() => intent({ action: { selector: TRANSFER_FROM_SELECTOR, hasAmount: true, amountIndex: 2 } }), { code: 'INVALID_STRUCTURE' });
  assert.throws(() => intent({ action: { selector: TRANSFER_FROM_SELECTOR, supported: false, hasAmount: true, amountIndex: 2 } }), { code: 'INVALID_ACTION' });
  assert.throws(() => intent({ action: { selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: false, amountIndex: 2 } }), { code: 'INVALID_ACTION' });
  assert.throws(() => intent({ action: { selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: true, amountIndex: 1 } }), { code: 'INVALID_ACTION' });
});

test('unknown fields and transfer identity tampering fail closed', () => {
  assert.throws(() => createTransferFromIntent({ ...policy(), authorize: true }, transfer()), { code: 'INVALID_STRUCTURE' });
  assert.throws(() => intent({ action: { ...policy().action, extra: true } }), { code: 'INVALID_STRUCTURE' });
  assert.throws(() => createTransferFromIntent(policy(), { ...transfer(), send: true }), { code: 'INVALID_STRUCTURE' });
  assert.throws(() => intent({}, { from: OTHER }), { code: 'TRANSFER_MISMATCH' });
  assert.throws(() => intent({}, { to: OTHER }), { code: 'TRANSFER_MISMATCH' });
  const changed = structuredClone(intent());
  changed.transfer.amount = '79';
  assert.throws(() => validateTransferFromIntent(changed), { code: 'INTENT_INTEGRITY' });
  const changedToken = structuredClone(intent());
  changedToken.policy.token = OTHER;
  assert.throws(() => validateTransferFromIntent(changedToken), { code: 'INTENT_INTEGRITY' });
});

test('raw BigInt caps, cumulative use and allowance are enforced without Number arithmetic', () => {
  assert.throws(() => intent({}, { amount: '0' }), { code: 'INVALID_UINT' });
  assert.throws(() => intent({}, { amount: '101' }), { code: 'TRANSACTION_CAP' });
  assert.throws(() => intent({ cumulativeUsed: '121' }), { code: 'CUMULATIVE_CAP' });
  assert.throws(() => intent({ allowance: '79' }), { code: 'ALLOWANCE' });
  assert.throws(() => intent({ maxTransactionValue: '201' }), { code: 'INVALID_CAPS' });
  assert.throws(() => intent({}, { amount: (1n << 256n).toString() }), { code: 'INVALID_UINT' });
  assert.throws(() => intent({}, { amount: '9'.repeat(10_000) }), { code: 'INVALID_UINT' });

  const max = (1n << 256n) - 1n;
  const huge = createTransferFromIntent(policy({
    maxTransactionValue: max,
    maxCumulativeValue: max,
    cumulativeUsed: 0n,
    allowance: max
  }), transfer({ amount: max }));
  assert.equal(huge.transfer.amount, max.toString());
  assert.equal(decodeTransferFrom(huge.innerCalldata).amount, max.toString());
});

test('expected transaction binds trusted outer bytes but remains explicitly unverified and unsigned', () => {
  const value = expected();
  assert.equal(value.transaction.chainId, SEPOLIA_CHAIN_ID);
  assert.equal(value.transaction.from, KNOWN_AGENT);
  assert.equal(value.transaction.to, EXECUTOR);
  assert.equal(value.transaction.value, '0');
  assert.equal(value.transaction.data, OUTER_CALLDATA);
  assert.equal(value.scope.outerEncoderAvailable, false);
  assert.equal(value.scope.outerCalldataVerified, false);
  assert.equal(value.scope.signingReady, false);
  assert.equal(value.scope.chainWriteAuthorized, false);
  assert.equal(value.transactionIntentHash.length, 64);
  assert.throws(() => expected(intent(), { outerCalldata: '0x' }), { code: 'INVALID_CALLDATA' });
  assert.throws(() => buildExpectedUnsignedTransaction(intent(), {
    outerCalldata: OUTER_CALLDATA, nonce: 7, gasLimit: 21000, type: 2,
    maxPriorityFeePerGas: 1, maxFeePerGas: 2, authorize: true
  }), { code: 'INVALID_STRUCTURE' });
  assert.throws(() => expected(intent(), { type: '2' }), { code: 'INVALID_TRANSACTION' });
  assert.throws(() => expected(intent(), { maxPriorityFeePerGas: 3, maxFeePerGas: 2 }), { code: 'INVALID_FEES' });
});

test('one exact prepared transaction validates while batches and unknown fields are rejected', () => {
  const expectedValue = expected();
  const result = validatePreparedTransactions(prepared(expectedValue), expectedValue);
  assert.equal(result.valid, true);
  assert.equal(result.signingReady, false);
  assert.equal(result.outerCalldataVerified, false);
  assert.throws(() => validatePreparedTransactions([], expectedValue), { code: 'BATCH_REJECTED' });
  assert.throws(() => validatePreparedTransactions([...prepared(expectedValue), ...prepared(expectedValue)], expectedValue), { code: 'BATCH_REJECTED' });
  const unknown = prepared(expectedValue); unknown[0].accessList = [];
  assert.throws(() => validatePreparedTransactions(unknown, expectedValue), { code: 'INVALID_STRUCTURE' });
});

test('prepared target, signer, chain, value and calldata tampering are rejected', () => {
  const expectedValue = expected();
  for (const [field, changed] of [
    ['to', OTHER],
    ['from', OTHER],
    ['chainId', '1'],
    ['value', '1'],
    ['data', OUTER_CALLDATA.slice(0, -2) + '13'],
    ['data', OUTER_CALLDATA + '00']
  ]) {
    const transactions = prepared(expectedValue);
    transactions[0][field] = changed;
    assert.throws(() => validatePreparedTransactions(transactions, expectedValue), { code: 'PREPARED_TRANSACTION_MISMATCH' });
  }
  const wrongType = prepared(expectedValue);
  wrongType[0].type = 1;
  assert.throws(() => validatePreparedTransactions(wrongType, expectedValue), { code: 'INVALID_TRANSACTION' });
});

test('two-argument prepared validation keeps nonce, gas and every EIP-1559 fee field exact', () => {
  const expectedValue = expected();
  for (const [field, changed] of [
    ['nonce', '8'],
    ['gasLimit', '21001'],
    ['maxPriorityFeePerGas', '1000001'],
    ['maxFeePerGas', '2000001']
  ]) {
    const transactions = prepared(expectedValue);
    transactions[0][field] = changed;
    assert.throws(() => validatePreparedTransactions(transactions, expectedValue), { code: 'PREPARED_TRANSACTION_MISMATCH' });
  }
});

test('explicit ceiling validation keeps exact fields bound and accepts only bounded gas and fees', () => {
  const expectedValue = expected();
  const ceilings = {
    gasLimit: expectedValue.transaction.gasLimit,
    maxPriorityFeePerGas: expectedValue.transaction.maxPriorityFeePerGas,
    maxFeePerGas: expectedValue.transaction.maxFeePerGas
  };
  const transactions = prepared(expectedValue);
  transactions[0].gasLimit = '20000';
  transactions[0].maxPriorityFeePerGas = '500000';
  transactions[0].maxFeePerGas = '1500000';
  assert.deepEqual(validatePreparedTransactions(transactions, expectedValue, ceilings).transaction, transactions[0]);

  const nonceMismatch = structuredClone(transactions); nonceMismatch[0].nonce = '8';
  assert.throws(() => validatePreparedTransactions(nonceMismatch, expectedValue, ceilings), {
    code: 'PREPARED_TRANSACTION_MISMATCH'
  });
  for (const [field, value] of [
    ['gasLimit', '21001'],
    ['maxPriorityFeePerGas', '1000001'],
    ['maxFeePerGas', '2000001']
  ]) {
    const over = structuredClone(transactions); over[0][field] = value;
    assert.throws(() => validatePreparedTransactions(over, expectedValue, ceilings), {
      code: 'PREPARED_TRANSACTION_CEILING'
    });
  }
  const invertedFees = structuredClone(transactions);
  invertedFees[0].maxPriorityFeePerGas = '1500001'; invertedFees[0].maxFeePerGas = '1500000';
  assert.throws(() => validatePreparedTransactions(invertedFees, expectedValue, ceilings), { code: 'INVALID_FEES' });
  assert.throws(() => validatePreparedTransactions(transactions, expectedValue, { ...ceilings, gasLimit: '21001' }), {
    code: 'TRANSACTION_CEILING_INTEGRITY'
  });
  assert.throws(() => validatePreparedTransactions(transactions, expectedValue, { ...ceilings, extra: '1' }), {
    code: 'INVALID_STRUCTURE'
  });
  for (const field of ['gasLimit', 'maxPriorityFeePerGas', 'maxFeePerGas']) {
    assert.throws(() => validatePreparedTransactions(transactions, expectedValue, { ...ceilings, [field]: '0' }), {
      code: 'INVALID_UINT'
    });
  }
});

test('intent and expected hashes reject amount and fee mutations even if transaction bytes remain unchanged', () => {
  const intentValue = intent();
  const changedIntent = structuredClone(intentValue);
  changedIntent.transfer.amount = '81';
  assert.throws(() => buildExpectedUnsignedTransaction(changedIntent, {
    outerCalldata: OUTER_CALLDATA,
    nonce: 7,
    gasLimit: 21000,
    type: 2,
    maxPriorityFeePerGas: 1,
    maxFeePerGas: 2
  }), { code: 'INTENT_INTEGRITY' });

  const expectedValue = expected();
  const changedExpected = structuredClone(expectedValue);
  changedExpected.transaction.maxFeePerGas = '2000001';
  assert.throws(() => validatePreparedTransactions(prepared(expectedValue), changedExpected), { code: 'TRANSACTION_INTENT_INTEGRITY' });
});
