import test from 'node:test';
import assert from 'node:assert/strict';
import { createTransferFromIntent, KNOWN_PRINCIPAL, KNOWN_AGENT, TRANSFER_FROM_SELECTOR, sha256Canonical } from '../src/brickken-intent.mjs';
import { buildOfflineExecutionCall, PROVISIONED_EXECUTOR } from '../src/brickken-executor.mjs';
import { buildExpectedExecutionPreparation, validateExecutePrepareResponse, validateExecutionPreparation, SANDBOX_IDENTITY_REF } from '../src/brickken-prepare.mjs';

function fixture() {
  const intent = createTransferFromIntent({ chainId: '11155111', principal: KNOWN_PRINCIPAL, agent: KNOWN_AGENT,
    executor: PROVISIONED_EXECUTOR, token: '0x5555555555555555555555555555555555555555', recipient: '0x6666666666666666666666666666666666666666',
    action: { selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: true, amountIndex: 2 },
    maxTransactionValue: '100', maxCumulativeValue: '200', cumulativeUsed: '0', allowance: '100'
  }, { from: KNOWN_PRINCIPAL, to: '0x6666666666666666666666666666666666666666', amount: '80' });
  const call = buildOfflineExecutionCall(intent);
  const binding = { nonce: '7', type: 2 };
  const context = { identityRef: SANDBOX_IDENTITY_REF, provisioningEvidenceSha256: 'a'.repeat(64),
    observedAt: 1800000000, expiresAt: 1800000300, maxGasLimit: '200000', maxPriorityFeePerGas: '1500000000',
    maxFeePerGas: '3000000000', maxTotalGasCost: '400000000000000' };
  const expected = buildExpectedExecutionPreparation(call, binding, context);
  const transaction = { ...expected.expected.transaction, gasLimit: '150000', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000' };
  const response = { transactions: [transaction], txId: 'fixture-batch-001' };
  const check = body => validateExecutePrepareResponse(JSON.stringify(body), expected, 1800000001);
  return { call, binding, context, expected, response, check };
}

test('prepare envelope binds one complete execution, identity reference, evidence and batch identity', () => {
  const { response, check, expected } = fixture();
  const result = check({ ...response, info: { untrusted: 'discard-me' } });
  assert.equal(result.txId, 'fixture-batch-001');
  assert.deepEqual(result.transaction, response.transactions[0]);
  assert.equal(result.transactionsContainerShape, 'array');
  assert.equal(result.identityRef, SANDBOX_IDENTITY_REF);
  assert.equal(result.expectationHash, expected.expectationHash);
  assert.equal(result.scope.abiSemanticsValidated, true);
  for (const key of ['livePrepareObserved', 'provisioningReady', 'signingReady', 'chainWriteAuthorized']) assert.equal(result.scope[key], false);
  assert.equal(result.scope.evidenceReferenceOnly, true);
  assert.equal(JSON.stringify(result).includes('discard-me'), false);
  assert.equal(Object.hasOwn(result, 'transactionHash'), false);
  const another = check({ ...response, txId: 'fixture-batch-002' });
  assert.notEqual(result.preparationHash, another.preparationHash);
  assert.deepEqual(check({ data: response }), check(response));
  assert.equal(expected.expected.transaction.gasLimit, '200000');
  assert.equal(expected.expected.transaction.maxPriorityFeePerGas, '1500000000');
  assert.equal(expected.expected.transaction.maxFeePerGas, '3000000000');
});

test('N2 revalidates the complete canonical preparation against trusted expectation, time and hash', () => {
  const { response, check, expected } = fixture();
  const original = check(response);
  assert.deepEqual(validateExecutionPreparation(
    structuredClone(original), expected, 1800000001, original.preparationHash
  ), original);
  const changes = [
    value => { value.schemaVersion = 2; },
    value => { value.kind = 'other'; },
    value => { value.txId = 'other-batch'; },
    value => { value.transactionsContainerShape = 'object'; },
    value => { value.transaction.chainId = '1'; },
    value => { value.transaction.from = KNOWN_PRINCIPAL; },
    value => { value.transaction.to = KNOWN_AGENT; },
    value => { value.transaction.value = '1'; },
    value => { value.transaction.data = '0x12345678'; },
    value => { value.transaction.nonce = '8'; },
    value => { value.transaction.gasLimit = '140000'; },
    value => { value.transaction.type = 0; },
    value => { value.transaction.maxPriorityFeePerGas = '900000000'; },
    value => { value.transaction.maxFeePerGas = '1900000000'; },
    value => { value.expectationHash = 'b'.repeat(64); },
    value => { value.identityRef = '0x' + 'b'.repeat(64); },
    value => { value.provisioningEvidenceSha256 = 'b'.repeat(64); },
    value => { value.expiresAt--; },
    value => { value.scope.signingReady = true; },
    value => { value.extra = true; }
  ];
  for (const mutate of changes) {
    const changed = structuredClone(original);
    mutate(changed);
    const { preparationHash: ignored, ...payload } = changed;
    changed.preparationHash = sha256Canonical(payload);
    assert.throws(() => validateExecutionPreparation(
      changed, expected, 1800000001, original.preparationHash
    ));
  }
  const changedHash = structuredClone(original);
  changedHash.preparationHash = 'b'.repeat(64);
  assert.throws(() => validateExecutionPreparation(
    changedHash, expected, 1800000001, original.preparationHash
  ), { code: 'PREPARATION_INTEGRITY' });
  const changedExpectation = structuredClone(expected);
  changedExpectation.context.expiresAt--;
  const { expectationHash: ignored, ...expectationPayload } = changedExpectation;
  changedExpectation.expectationHash = sha256Canonical(expectationPayload);
  assert.throws(() => validateExecutionPreparation(
    original, changedExpectation, 1800000001, original.preparationHash
  ));
  for (const badHash of [undefined, original.preparationHash.toUpperCase(), '0'.repeat(63)]) {
    assert.throws(() => validateExecutionPreparation(original, expected, 1800000001, badHash), {
      code: 'TRUSTED_PREPARATION_HASH'
    });
  }
  assert.throws(() => validateExecutionPreparation(
    original, expected, 1800000300, original.preparationHash
  ), { code: 'EXPECTATION_EXPIRED' });
});

test('documented RAMS transaction object and generic array-of-one are both closed and typed', () => {
  const { response, check } = fixture();
  const objectResult = check({ data: { ...response, transactions: response.transactions[0] } });
  assert.equal(objectResult.transactionsContainerShape, 'object');
  assert.deepEqual(objectResult.transaction, response.transactions[0]);
  assert.equal(check(response).transactionsContainerShape, 'array');

  assert.throws(() => check({ ...response, transactions: { ...response.transactions[0], extra: true } }));
  assert.throws(() => check({ ...response, transactions: [response.transactions[0], response.transactions[0]] }), {
    code: 'BATCH_REJECTED'
  });
});

test('documented primitive and exact BigNumber numeric forms normalize without losing precision', () => {
  const { response, check } = fixture();
  const tx = response.transactions[0];
  tx.chainId = 11155111; tx.nonce = 7; tx.value = '0x00';
  tx.gasLimit = { type: 'BigNumber', hex: '0x249f0' };
  tx.maxPriorityFeePerGas = { type: 'BigNumber', hex: '0x3b9aca00' };
  tx.maxFeePerGas = '0x77359400';
  assert.equal(check(response).transaction.gasLimit, '150000');
});

test('every exact transaction field mutation, signing field and extra transaction is rejected', () => {
  const changes = { chainId: '1', from: KNOWN_PRINCIPAL, to: KNOWN_AGENT, value: '1', data: '0x12345678',
    nonce: '8', type: 0 };
  for (const [key, value] of Object.entries(changes)) {
    const { response, check } = fixture(); response.transactions[0][key] = value;
    assert.throws(() => check(response), key);
  }
  for (const key of ['accessList', 'gasPrice', 'r', 's', 'v', 'authorizationList']) {
    const { response, check } = fixture(); response.transactions[0][key] = '0';
    assert.throws(() => check(response), key);
  }
  for (const count of [0, 2]) {
    const { response, check } = fixture(); response.transactions = Array(count).fill(response.transactions[0]);
    assert.throws(() => check(response));
  }
});

test('ambiguous containers, errors, partial objects and invalid batch identifiers fail closed', () => {
  const { response, check } = fixture();
  for (const body of [null, [], {}, { data: null }, { data: { data: response } }, { ...response, error: 'secret-sentinel' },
    { ...response, data: response }, { ...response, result: true }, { ...response, info: [] },
    { ...response, transactions: [{}] }]) assert.throws(() => check(body));
  for (const txId of ['', 'a'.repeat(129), '../relative', 'line\nbreak', 1, null]) assert.throws(() => check({ ...response, txId }));
});

test('an x402Requirements quote in any documented position is read as data and accepts JSON values without changing the transaction', () => {
  const { response, check } = fixture();
  const quote = { scheme: 'exact', network: 'eip155:84532', asset: 'USDC', maxAmountRequired: '250000' };
  for (const body of [{ ...response, x402Requirements: quote }, { data: response, x402Requirements: quote },
    { data: { ...response, x402Requirements: quote } }]) {
    assert.doesNotThrow(() => check(body));
  }
  // The documentation does not fix the quote's shape; every JSON form is data.
  for (const other of ['pay', [{ scheme: 'exact' }], null, 1, true]) {
    assert.doesNotThrow(() => check({ ...response, x402Requirements: other }), String(other));
  }
});

test('round5: a null quote beside a data wrapper is absent metadata and keeps the preparation hash unchanged', () => {
  const { response, check } = fixture();
  assert.deepEqual(check({ data: response, x402Requirements: null }), check({ data: response }));
  assert.throws(() => check({ data: response, x402Requirements: null, surprise: true }), { code: 'STRUCTURE' });
});

test('invalid exact integers and BigNumber objects are rejected', () => {
  for (const amount of [-1, 1.1, Number.MAX_SAFE_INTEGER + 1, '01', '1e3', '-1', '0x', '0x' + 'f'.repeat(65),
    { type: 'BigNumber', hex: '0x00', other: true }, { _hex: '0x00' }, { type: 'Other', hex: '0x00' }]) {
    const { response, check } = fixture(); response.transactions[0].value = amount;
    assert.throws(() => check(response));
  }
});

test('stale, future, extended-window and identity-drift expectations cannot validate', () => {
  const { response, expected, call, binding, context } = fixture();
  for (const now of [1799999999, 1800000300, 1800000301, 0, NaN]) {
    assert.throws(() => validateExecutePrepareResponse(JSON.stringify(response), expected, now));
  }
  for (const change of [{ identityRef: '0x' + 'b'.repeat(64) }, { provisioningEvidenceSha256: 'bad' },
    { expiresAt: 1800000301 }, { expiresAt: 1800000000 }]) {
    assert.throws(() => buildExpectedExecutionPreparation(call, binding, { ...context, ...change }));
  }
  const tampered = structuredClone(expected); tampered.scope.signingReady = true;
  assert.throws(() => validateExecutePrepareResponse(JSON.stringify(response), tampered, 1800000001));
  const changedContextCeiling = structuredClone(expected); changedContextCeiling.context.maxPriorityFeePerGas = '1499999999';
  assert.throws(() => validateExecutePrepareResponse(JSON.stringify(response), changedContextCeiling, 1800000001));
  for (const field of ['gasLimit', 'maxPriorityFeePerGas', 'maxFeePerGas']) {
    const changedExpectedCeiling = structuredClone(expected);
    changedExpectedCeiling.expected.transaction[field] = (BigInt(changedExpectedCeiling.expected.transaction[field]) - 1n).toString();
    assert.throws(() => validateExecutePrepareResponse(JSON.stringify(response), changedExpectedCeiling, 1800000001));
  }
});

test('caller-selected gas, priority-fee, max-fee and total-cost ceilings are closed and coherent', () => {
  const { call, binding, context } = fixture();
  for (const change of [{ maxGasLimit: '0' }, { maxPriorityFeePerGas: '0' }, { maxFeePerGas: '0' },
    { maxTotalGasCost: '0' }, { maxPriorityFeePerGas: '3000000001' }]) {
    assert.throws(() => buildExpectedExecutionPreparation(call, binding, { ...context, ...change }));
  }
  assert.throws(() => buildExpectedExecutionPreparation(call, { ...binding, gasLimit: '150000' }, context));
});

test('response gas and fees may vary within every ceiling while exact fields stay bound', () => {
  const { response, check } = fixture();
  const within = structuredClone(response);
  within.transactions[0].gasLimit = '175000';
  within.transactions[0].maxPriorityFeePerGas = '1200000000';
  within.transactions[0].maxFeePerGas = '2100000000';
  assert.deepEqual(check(within).transaction, within.transactions[0]);
  const exactTotalBoundary = structuredClone(response);
  exactTotalBoundary.transactions[0].gasLimit = '200000';
  exactTotalBoundary.transactions[0].maxPriorityFeePerGas = '1500000000';
  exactTotalBoundary.transactions[0].maxFeePerGas = '2000000000';
  assert.deepEqual(check(exactTotalBoundary).transaction, exactTotalBoundary.transactions[0]);

  const nonceMismatch = structuredClone(response); nonceMismatch.transactions[0].nonce = '8';
  assert.throws(() => check(nonceMismatch));

  for (const change of [
    { gasLimit: '200001' },
    { maxPriorityFeePerGas: '1500000001' },
    { maxFeePerGas: '3000000001' },
    { gasLimit: '200000', maxFeePerGas: '2500000000' },
    { maxPriorityFeePerGas: '1100000000', maxFeePerGas: '1000000000' }
  ]) {
    const over = structuredClone(response);
    Object.assign(over.transactions[0], change);
    assert.throws(() => check(over));
  }
});

test('malformed and oversized response diagnostics do not echo response contents', () => {
  const { expected } = fixture();
  for (const body of ['secret-sentinel', 'x'.repeat(65537), '{"transactions":']) {
    assert.throws(() => validateExecutePrepareResponse(body, expected, 1800000001), error => {
      assert.equal(error.message.includes('secret-sentinel'), false);
      return true;
    });
  }
});
