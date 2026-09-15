// Independent test suite for the live Brickken HTTP surface added on 2026-09-14:
// RAMS facade prepare calls, the client-signed send call, the transaction status
// call, their response parsers, and the postcheck live-scope option. This file
// does not touch the network: every fetchImpl is a fake that returns
// `new Response(...)` or a plain mock object, injected in memory only.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BRICKKEN_SANDBOX_ORIGIN,
  BRICKKEN_PREPARE_URL,
  BRICKKEN_RAMS_PREPARE_PATHS,
  BRICKKEN_SEND_URL,
  BRICKKEN_STATUS_URL,
  BrickkenHttpError,
  postBrickkenPrepare,
  postBrickkenRamsPrepare,
  postBrickkenSend,
  getBrickkenTransactionStatus,
  parseBrickkenSendResponse,
  parseBrickkenStatusResponse
} from '../src/brickken-http.mjs';
import { parseRamsPrepareResponse, BrickkenPrepareError } from '../src/brickken-prepare.mjs';
import { EVENT_TOPICS, verifyApprovePostcheck } from '../src/brickken-postcheck.mjs';

const SECRET = 'fixture-api-key-secret-sentinel';
const RAMS_BODY = { agent: '0x' + '1'.repeat(40) };
const RAMS_URL_GRANT = BRICKKEN_SANDBOX_ORIGIN + BRICKKEN_RAMS_PREPARE_PATHS.grant;

// A response whose `.body` getter throws if ever touched, so a test proves a
// given status is classified without reading the response body at all.
function silentBodyResponse(status, url = RAMS_URL_GRANT) {
  const response = { status, redirected: false, url, headers: { get: () => null } };
  Object.defineProperty(response, 'body', {
    get() { throw new Error('response body must not be read for status ' + status); }
  });
  return response;
}

// =====================================================================
// postBrickkenRamsPrepare: routing, headers and method for all four ops
// =====================================================================

test('postBrickkenRamsPrepare posts each of the four documented operations to its fixed sandbox path with only the three declared headers', async () => {
  for (const [operation, path] of Object.entries(BRICKKEN_RAMS_PREPARE_PATHS)) {
    let observed;
    const fetchImpl = async (url, options) => {
      observed = { url, options };
      return new Response('{"transactions":{},"txId":"fixture"}', { status: 200 });
    };
    await postBrickkenRamsPrepare({ credential: SECRET, operation, body: RAMS_BODY, fetchImpl });
    assert.equal(observed.url, BRICKKEN_SANDBOX_ORIGIN + path, operation);
    assert.equal(observed.options.method, 'POST', operation);
    assert.equal(observed.options.redirect, 'error', operation);
    assert.equal(observed.options.credentials, 'omit', operation);
    assert.deepEqual(Object.keys(observed.options.headers).sort(), ['accept', 'content-type', 'x-api-key'], operation);
    assert.equal(observed.options.headers['x-api-key'], SECRET, operation);
    assert.deepEqual(JSON.parse(observed.options.body), RAMS_BODY, operation);
  }
});

test('postBrickkenRamsPrepare rejects an unknown or inherited operation name with OPERATION_DENIED before fetch', async () => {
  let called = false;
  const fetchImpl = async () => { called = true; return new Response('{}', { status: 200 }); };
  for (const operation of ['transferFrom', '__proto__', 'toString', 'constructor', '', 42, null, undefined]) {
    called = false;
    await assert.rejects(
      postBrickkenRamsPrepare({ credential: SECRET, operation, body: RAMS_BODY, fetchImpl }),
      { code: 'OPERATION_DENIED' },
      String(operation)
    );
    assert.equal(called, false, String(operation));
  }
});

// =====================================================================
// postBrickkenRamsPrepare: status classification (shared by send/status too)
// =====================================================================

test('postBrickkenRamsPrepare classifies 402, 401, 403 and 429 without ever reading the response body', async () => {
  const cases = new Map([
    [402, 'PAYMENT_REQUIRED'], [401, 'AUTHORIZATION_DENIED'],
    [403, 'AUTHORIZATION_DENIED'], [429, 'RATE_LIMITED']
  ]);
  for (const [status, code] of cases) {
    await assert.rejects(
      postBrickkenRamsPrepare({ credential: SECRET, operation: 'grant', body: RAMS_BODY, fetchImpl: async () => silentBodyResponse(status) }),
      error => {
        assert.equal(error instanceof BrickkenHttpError, true);
        assert.equal(error.code, code);
        assert.equal(error.status, status);
        return true;
      }
    );
  }
});

test('postBrickkenRamsPrepare extracts a documented machine error code on 400 and never leaks the message text', async () => {
  const withCode = new Response(JSON.stringify({ error: { code: 'MANDATE_NOT_FOUND', message: 'secret-detail-code' } }), { status: 400 });
  await assert.rejects(
    postBrickkenRamsPrepare({ credential: SECRET, operation: 'grant', body: RAMS_BODY, fetchImpl: async () => withCode }),
    error => {
      assert.equal(error.code, 'HTTP_REJECTED');
      assert.equal(error.status, 400);
      assert.equal(error.apiErrorCode, 'MANDATE_NOT_FOUND');
      assert.equal(error.message.includes('secret-detail-code'), false);
      return true;
    }
  );

  const spacedCode = new Response(JSON.stringify({ error: { code: 'invalid code', message: 'secret-detail-spaced' } }), { status: 400 });
  await assert.rejects(
    postBrickkenRamsPrepare({ credential: SECRET, operation: 'grant', body: RAMS_BODY, fetchImpl: async () => spacedCode }),
    error => {
      assert.equal(error.apiErrorCode, null);
      assert.equal(error.message.includes('secret-detail-spaced'), false);
      return true;
    }
  );

  const messageOnly = new Response(JSON.stringify({ error: { message: 'secret-detail-message-only' } }), { status: 400 });
  await assert.rejects(
    postBrickkenRamsPrepare({ credential: SECRET, operation: 'grant', body: RAMS_BODY, fetchImpl: async () => messageOnly }),
    error => {
      assert.equal(error.apiErrorCode, null);
      assert.equal(error.message.includes('secret-detail-message-only'), false);
      return true;
    }
  );
});

test('postBrickkenRamsPrepare classifies a bare 500 as HTTP_REJECTED', async () => {
  await assert.rejects(
    postBrickkenRamsPrepare({ credential: SECRET, operation: 'grant', body: RAMS_BODY, fetchImpl: async () => silentBodyResponse(500) }),
    { code: 'HTTP_REJECTED', status: 500 }
  );
});

// =====================================================================
// postBrickkenRamsPrepare: redirect, oversize response, timeout, credential
// =====================================================================

test('postBrickkenRamsPrepare rejects a redirected response', async () => {
  await assert.rejects(
    postBrickkenRamsPrepare({
      credential: SECRET, operation: 'grant', body: RAMS_BODY,
      fetchImpl: async () => ({ status: 200, redirected: true, url: 'https://example.invalid/', headers: { get: () => null } })
    }),
    { code: 'REDIRECT_REJECTED' }
  );
});

// The live routes classify a non-200 status before the redirect check, exactly
// like postBrickkenPrepare, so the same wire condition gives the same code on
// both paths. A redirected 200 is still rejected before its body is read.
test('live routes classify a redirected 402 as PAYMENT_REQUIRED and reject a redirected 200', async () => {
  const redirectedPaymentRequired = { status: 402, redirected: true, url: 'https://example.invalid/', headers: { get: () => null } };
  await assert.rejects(
    postBrickkenRamsPrepare({ credential: SECRET, operation: 'grant', body: RAMS_BODY, fetchImpl: async () => redirectedPaymentRequired }),
    { code: 'PAYMENT_REQUIRED' }
  );
  const redirectedOk = { status: 200, redirected: true, url: 'https://example.invalid/', headers: { get: () => null } };
  Object.defineProperty(redirectedOk, 'body', { get() { throw new Error('must not read'); } });
  await assert.rejects(
    postBrickkenRamsPrepare({ credential: SECRET, operation: 'grant', body: RAMS_BODY, fetchImpl: async () => redirectedOk }),
    { code: 'REDIRECT_REJECTED' }
  );
});

test('postBrickkenRamsPrepare rejects an oversized declared content-length on a 200 response without reading the body', async () => {
  const response = {
    status: 200, redirected: false, url: RAMS_URL_GRANT,
    headers: { get: name => name === 'content-length' ? '999999' : null }
  };
  Object.defineProperty(response, 'body', { get() { throw new Error('must not read'); } });
  await assert.rejects(
    postBrickkenRamsPrepare({ credential: SECRET, operation: 'grant', body: RAMS_BODY, fetchImpl: async () => response, maxResponseBytes: 100 }),
    { code: 'RESPONSE_TOO_LARGE' }
  );
});

test('getBrickkenTransactionStatus times out the owned request without exposing the credential', async () => {
  const hash = '0x' + '7'.repeat(64);
  let signal;
  await assert.rejects(
    getBrickkenTransactionStatus({
      credential: SECRET, transactionHash: hash, timeoutMs: 10,
      fetchImpl: async (_url, options) => { signal = options.signal; return await new Promise(() => {}); }
    }),
    error => {
      assert.equal(error.code, 'HTTP_TIMEOUT');
      assert.equal(error.message.includes(SECRET), false);
      return true;
    }
  );
  assert.equal(signal.aborted, true);
});

test('postBrickkenRamsPrepare rejects an invalid credential before fetch is called', async () => {
  for (const bad of ['', 'line\nbreak', null, 1]) {
    let called = false;
    await assert.rejects(
      postBrickkenRamsPrepare({
        credential: bad, operation: 'grant', body: RAMS_BODY,
        fetchImpl: async () => { called = true; return new Response('{}', { status: 200 }); }
      }),
      { code: 'CREDENTIAL_INVALID' },
      String(bad)
    );
    assert.equal(called, false, String(bad));
  }
});

// =====================================================================
// postBrickkenSend
// =====================================================================

test('postBrickkenSend body is exactly {"txId":...,"signedTransactions":...}', async () => {
  let observed;
  const fetchImpl = async (url, options) => {
    observed = { url, options };
    return new Response(JSON.stringify({ txHash: '0x' + 'a'.repeat(64), status: 'pending' }), { status: 200 });
  };
  const txId = 'txid-fixture-001';
  const signedTransaction = '0x' + 'ab'.repeat(40);
  const result = await postBrickkenSend({ credential: SECRET, txId, signedTransaction, fetchImpl });
  assert.equal(observed.url, BRICKKEN_SEND_URL);
  assert.equal(observed.options.method, 'POST');
  assert.equal(observed.options.body, JSON.stringify({ txId, signedTransactions: signedTransaction }));
  assert.deepEqual(Object.keys(observed.options.headers).sort(), ['accept', 'content-type', 'x-api-key']);
  assert.equal(result, JSON.stringify({ txHash: '0x' + 'a'.repeat(64), status: 'pending' }));
});

test('postBrickkenSend rejects uppercase hex, odd length, a missing 0x prefix and an invalid txId before fetch', async () => {
  let called = false;
  const fetchImpl = async () => { called = true; return new Response('{}', { status: 200 }); };
  const validSigned = '0x' + 'ab'.repeat(10);
  const cases = [
    { label: 'uppercase hex', txId: 'ok', signedTransaction: '0x' + 'AB'.repeat(10) },
    { label: 'odd length', txId: 'ok', signedTransaction: '0x' + 'abc' },
    { label: 'missing 0x', txId: 'ok', signedTransaction: 'ab'.repeat(10) },
    { label: 'empty txId', txId: '', signedTransaction: validSigned },
    { label: 'txId with space', txId: 'bad id with space', signedTransaction: validSigned },
    { label: 'txId too long', txId: 'x'.repeat(129), signedTransaction: validSigned }
  ];
  for (const { label, txId, signedTransaction } of cases) {
    called = false;
    await assert.rejects(
      postBrickkenSend({ credential: SECRET, txId, signedTransaction, fetchImpl }),
      error => { assert.equal(error instanceof BrickkenHttpError, true); return true; },
      label
    );
    assert.equal(called, false, label);
  }
});

// =====================================================================
// getBrickkenTransactionStatus
// =====================================================================

test('getBrickkenTransactionStatus issues a bodyless GET whose URL ends with ?hash= plus the lowercase hash', async () => {
  let observed;
  const hash = '0x' + '5'.repeat(64);
  const fetchImpl = async (url, options) => {
    observed = { url, options };
    return new Response(JSON.stringify({ status: 'pending', transactionHash: hash }), { status: 200 });
  };
  await getBrickkenTransactionStatus({ credential: SECRET, transactionHash: hash, fetchImpl });
  assert.equal(observed.url, BRICKKEN_STATUS_URL + '?hash=' + hash);
  assert.equal(observed.options.method, 'GET');
  assert.equal(Object.hasOwn(observed.options, 'body'), false);
  assert.deepEqual(Object.keys(observed.options.headers).sort(), ['accept', 'x-api-key']);
});

test('getBrickkenTransactionStatus rejects an uppercase or wrong-length hash before fetch', async () => {
  let called = false;
  const fetchImpl = async () => { called = true; return new Response('{}', { status: 200 }); };
  for (const bad of ['0x' + '5'.repeat(63), '0x' + 'A'.repeat(64), '5'.repeat(64), '0x' + '5'.repeat(65)]) {
    called = false;
    await assert.rejects(
      getBrickkenTransactionStatus({ credential: SECRET, transactionHash: bad, fetchImpl }),
      { code: 'TRANSACTION_HASH_INVALID' },
      bad
    );
    assert.equal(called, false, bad);
  }
});

// =====================================================================
// parseBrickkenSendResponse / parseBrickkenStatusResponse
// =====================================================================

test('parseBrickkenSendResponse normalizes root and data-wrapped forms and lowercases the hash', () => {
  const hash = '0x' + 'AB'.repeat(32);
  const rootForm = parseBrickkenSendResponse(JSON.stringify({ txHash: hash, status: 'pending' }));
  assert.equal(rootForm.txHash, hash.toLowerCase());
  assert.equal(rootForm.status, 'pending');
  const wrapped = parseBrickkenSendResponse(JSON.stringify({ data: { txHash: hash, status: 'pending' } }));
  assert.deepEqual(wrapped, rootForm);
});

test('parseBrickkenSendResponse rejects an invalid hash and a data wrapper with a sibling key', () => {
  assert.throws(() => parseBrickkenSendResponse(JSON.stringify({ txHash: '0xzz', status: 'pending' })), { code: 'RESPONSE_INVALID' });
  assert.throws(
    () => parseBrickkenSendResponse(JSON.stringify({ data: { txHash: '0x' + 'a'.repeat(64), status: 'pending' }, extra: 1 })),
    { code: 'RESPONSE_INVALID' }
  );
});

test('parseBrickkenSendResponse normalizes malformed or non-string status values to null and never returns free text', () => {
  const hash = '0x' + 'a'.repeat(64);
  for (const status of ['Pending', 'processing_now!', 123, null, {}]) {
    const result = parseBrickkenSendResponse(JSON.stringify({ txHash: hash, status }));
    assert.equal(result.status, null, JSON.stringify(status));
  }
  const missingStatus = parseBrickkenSendResponse(JSON.stringify({ txHash: hash }));
  assert.equal(missingStatus.status, null);
  const withMessage = parseBrickkenSendResponse(JSON.stringify({ txHash: hash, status: 'pending', message: 'secret-sentinel-text' }));
  assert.equal(JSON.stringify(withMessage).includes('secret-sentinel'), false);
});

// OBSERVATION, not asserted as a defect: parseBrickkenSendResponse has no enum
// restriction on `status` (any lowercase/underscore/hyphen string up to 32
// chars is accepted verbatim), unlike parseBrickkenStatusResponse below, which
// only accepts pending/success/rejected and throws on anything else. A caller
// cannot rely on the send-response `status` being one of a known set.
test('parseBrickkenSendResponse accepts any well-formed status string, not only a documented set', () => {
  const hash = '0x' + 'a'.repeat(64);
  const result = parseBrickkenSendResponse(JSON.stringify({ txHash: hash, status: 'expired' }));
  assert.equal(result.status, 'expired');
});

test('parseBrickkenStatusResponse normalizes root and data-wrapped forms, lowercases the hash and reports error as boolean only', () => {
  const hash = '0x' + 'CD'.repeat(32);
  const body = { status: 'success', transactionHash: hash, error: 'revert: secret-detail-xyz' };
  const result = parseBrickkenStatusResponse(JSON.stringify(body));
  assert.equal(result.status, 'success');
  assert.equal(result.transactionHash, hash.toLowerCase());
  assert.equal(result.errorReported, true);
  assert.equal(JSON.stringify(result).includes('secret-detail-xyz'), false);
  const wrapped = parseBrickkenStatusResponse(JSON.stringify({ data: body }));
  assert.deepEqual(wrapped, result);
});

test('parseBrickkenStatusResponse rejects an invalid hash, an unknown status and a data wrapper with a sibling key', () => {
  const hash = '0x' + 'e'.repeat(64);
  assert.throws(() => parseBrickkenStatusResponse(JSON.stringify({ status: 'processing', transactionHash: hash })), { code: 'RESPONSE_INVALID' });
  assert.throws(() => parseBrickkenStatusResponse(JSON.stringify({ status: 'success', transactionHash: '0xzz' })), { code: 'RESPONSE_INVALID' });
  assert.throws(
    () => parseBrickkenStatusResponse(JSON.stringify({ data: { status: 'success', transactionHash: hash }, extra: true })),
    { code: 'RESPONSE_INVALID' }
  );
});

test('parseBrickkenStatusResponse treats a missing or null transactionHash as absent and an empty error as not reported', () => {
  const noHash = parseBrickkenStatusResponse(JSON.stringify({ status: 'pending' }));
  assert.equal(noHash.transactionHash, null);
  assert.equal(noHash.errorReported, false);
  const nullHash = parseBrickkenStatusResponse(JSON.stringify({ status: 'pending', transactionHash: null }));
  assert.equal(nullHash.transactionHash, null);
  const emptyError = parseBrickkenStatusResponse(JSON.stringify({ status: 'pending', error: '' }));
  assert.equal(emptyError.errorReported, false);
});

// =====================================================================
// parseRamsPrepareResponse
// =====================================================================

const RAMS_FROM = '0x' + 'Aa'.repeat(20);
const RAMS_TO = '0x' + 'Bb'.repeat(20);
const RAMS_CONTRACT = '0x' + 'Cc'.repeat(20);

function ramsTransaction(overrides = {}) {
  return {
    chainId: 11155111,
    from: RAMS_FROM,
    to: RAMS_TO,
    value: '0',
    data: '0x1234ABCD',
    nonce: 7,
    gasLimit: 200000,
    type: 2,
    maxPriorityFeePerGas: 1000000000,
    maxFeePerGas: 2000000000,
    ...overrides
  };
}

test('parseRamsPrepareResponse accepts the documented data-wrapped single-transaction-object form', () => {
  const body = JSON.stringify({
    data: {
      transactions: ramsTransaction(),
      txId: 'rams-fixture-001',
      info: { contractAddress: RAMS_CONTRACT, mode: 'direct' }
    }
  });
  const result = parseRamsPrepareResponse(body);
  assert.equal(result.txId, 'rams-fixture-001');
  assert.equal(result.transactionsContainerShape, 'object');
  assert.equal(result.transaction.from, RAMS_FROM.toLowerCase());
  assert.equal(result.transaction.to, RAMS_TO.toLowerCase());
  assert.equal(result.transaction.data, '0x1234abcd');
  assert.equal(result.transaction.chainId, '11155111');
  assert.equal(result.transaction.nonce, '7');
  assert.equal(result.transaction.gasLimit, '200000');
  assert.equal(result.transaction.type, 2);
  assert.equal(result.mode, 'direct');
  assert.equal(result.contractAddress, RAMS_CONTRACT.toLowerCase());
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.transaction), true);
});

test('parseRamsPrepareResponse accepts the single-element array form at the response root, with no info', () => {
  const body = JSON.stringify({ transactions: [ramsTransaction()], txId: 'rams-fixture-002' });
  const result = parseRamsPrepareResponse(body);
  assert.equal(result.transactionsContainerShape, 'array');
  assert.equal(result.mode, null);
  assert.equal(result.contractAddress, null);
});

test('parseRamsPrepareResponse normalizes BigNumber objects and hex numeric strings to decimal without losing precision', () => {
  const body = JSON.stringify({
    data: {
      transactions: ramsTransaction({
        value: '0xff',
        gasLimit: { type: 'BigNumber', hex: '0x30d40' }, // 200000
        maxPriorityFeePerGas: '0x3b9aca00', // 1000000000
        maxFeePerGas: { type: 'BigNumber', hex: '0x77359400' } // 2000000000
      }),
      txId: 'rams-fixture-003'
    }
  });
  const result = parseRamsPrepareResponse(body);
  assert.equal(result.transaction.value, '255');
  assert.equal(result.transaction.gasLimit, '200000');
  assert.equal(result.transaction.maxPriorityFeePerGas, '1000000000');
  assert.equal(result.transaction.maxFeePerGas, '2000000000');
});

test('parseRamsPrepareResponse rejects a relayed or principal-signature mode and accepts direct', () => {
  for (const mode of ['brickken-relayed', 'principal-signature']) {
    const body = JSON.stringify({ data: { transactions: ramsTransaction(), txId: 'rams-fixture-004', info: { mode } } });
    assert.throws(() => parseRamsPrepareResponse(body), { code: 'MODE_REJECTED' }, mode);
  }
  const direct = JSON.stringify({ data: { transactions: ramsTransaction(), txId: 'rams-fixture-005', info: { mode: 'direct' } } });
  assert.equal(parseRamsPrepareResponse(direct).mode, 'direct');
});

test('parseRamsPrepareResponse stops at a payment requirement whether it appears at the root or inside data', () => {
  const inner = { transactions: ramsTransaction(), txId: 'rams-fixture-006' };
  for (const body of [
    JSON.stringify({ ...inner, x402Requirements: {} }),
    JSON.stringify({ data: inner, x402Requirements: {} }),
    JSON.stringify({ data: { ...inner, x402Requirements: {} } })
  ]) {
    assert.throws(() => parseRamsPrepareResponse(body), { code: 'PAYMENT_REVIEW_REQUIRED' });
  }
});

test('parseRamsPrepareResponse rejects an extra or missing transaction key, wrong type discriminant, two-transaction batches, a non-string txId, and invalid JSON, never as a raw SyntaxError', () => {
  const base = () => ({ data: { transactions: ramsTransaction(), txId: 'rams-fixture-007' } });

  const withExtraKey = base();
  withExtraKey.data.transactions = { ...ramsTransaction(), gasPrice: '1' };
  assert.throws(() => parseRamsPrepareResponse(JSON.stringify(withExtraKey)), { code: 'STRUCTURE' });

  const withMissingKey = base();
  const { nonce: _dropped, ...incomplete } = ramsTransaction();
  withMissingKey.data.transactions = incomplete;
  assert.throws(() => parseRamsPrepareResponse(JSON.stringify(withMissingKey)), { code: 'STRUCTURE' });

  const typeZero = base();
  typeZero.data.transactions = ramsTransaction({ type: 0 });
  assert.throws(() => parseRamsPrepareResponse(JSON.stringify(typeZero)), { code: 'TRANSACTION_TYPE' });

  const typeString = base();
  typeString.data.transactions = ramsTransaction({ type: '2' });
  assert.throws(() => parseRamsPrepareResponse(JSON.stringify(typeString)), { code: 'TRANSACTION_TYPE' });

  const twoTransactions = base();
  twoTransactions.data.transactions = [ramsTransaction(), ramsTransaction()];
  assert.throws(() => parseRamsPrepareResponse(JSON.stringify(twoTransactions)), { code: 'BATCH_REJECTED' });

  const numericTxId = base();
  numericTxId.data.txId = 12345;
  assert.throws(() => parseRamsPrepareResponse(JSON.stringify(numericTxId)), { code: 'TX_ID' });

  assert.throws(() => parseRamsPrepareResponse('{not-json'), error => {
    assert.equal(error instanceof BrickkenPrepareError, true);
    assert.notEqual(error.constructor.name, 'SyntaxError');
    assert.equal(error.code, 'PREPARATION_REJECTED');
    return true;
  });
});

// The OpenAPI response schema declares info with additionalProperties: true and
// names advisories and eip712Nonce as possible members, so info stays open by
// design: only mode and contractAddress are read and nothing else is returned.
test('parseRamsPrepareResponse reads only mode and contractAddress from the open info object', () => {
  const body = JSON.stringify({
    data: {
      transactions: ramsTransaction(),
      txId: 'rams-fixture-008',
      info: { contractAddress: RAMS_CONTRACT, mode: 'direct', unexpectedField: 'should-not-pass-silently' }
    }
  });
  const result = parseRamsPrepareResponse(body);
  assert.equal(result.mode, 'direct');
  assert.equal(result.contractAddress, RAMS_CONTRACT.toLowerCase());
});

// =====================================================================
// Postcheck live-scope option (brickken-postcheck.mjs)
// =====================================================================

const PC_TX_HASH = '0x' + '1'.repeat(64);
const PC_BLOCK_HASH = '0x' + '2'.repeat(64);
const PC_BEFORE_HASH = '0x' + '3'.repeat(64);
const PC_PRINCIPAL = '0x1111111111111111111111111111111111111111';
const PC_SPENDER = '0x3333333333333333333333333333333333333333';
const PC_TOKEN = '0x5555555555555555555555555555555555555555';

function pcWordUint(value) { return BigInt(value).toString(16).padStart(64, '0'); }
function pcWordAddress(value) { return '0'.repeat(24) + value.slice(2).toLowerCase(); }
function pcTopicAddress(value) { return '0x' + pcWordAddress(value); }
function approveCallData() { return '0x095ea7b3' + pcWordAddress(PC_SPENDER) + pcWordUint(10000); }

function approveEnvelope() {
  const expected = {
    hash: PC_TX_HASH, chainId: '11155111', from: PC_PRINCIPAL, to: PC_TOKEN, value: '0', data: approveCallData(),
    nonce: '7', type: 2, gasLimit: '200000', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000'
  };
  const approvalLog = {
    address: PC_TOKEN, topics: [EVENT_TOPICS.Approval, pcTopicAddress(PC_PRINCIPAL), pcTopicAddress(PC_SPENDER)],
    data: '0x' + pcWordUint(10000), transactionHash: PC_TX_HASH, blockNumber: '100', blockHash: PC_BLOCK_HASH,
    logIndex: '0', removed: false
  };
  return {
    schemaVersion: 1, operationKind: 'approve',
    expected: { transaction: expected, semantics: { token: PC_TOKEN, owner: PC_PRINCIPAL, spender: PC_SPENDER, amount: '10000' } },
    transaction: { ...expected, blockNumber: '100', blockHash: PC_BLOCK_HASH },
    receipt: {
      transactionHash: PC_TX_HASH, status: 1, from: PC_PRINCIPAL, to: PC_TOKEN,
      blockNumber: '100', blockHash: PC_BLOCK_HASH, logs: [approvalLog]
    },
    before: { blockNumber: '99', blockHash: PC_BEFORE_HASH, state: { allowance: '0' } },
    after: { blockNumber: '100', blockHash: PC_BLOCK_HASH, state: { allowance: '10000' } },
    observedAt: '2026-09-14T12:00:00.000Z'
  };
}

test('verifyApprovePostcheck reports the live scope only when options.observationSource is sepolia-rpc-block-bound', () => {
  const input = approveEnvelope();

  const fixtureReport = verifyApprovePostcheck(input, input.expected);
  assert.equal(fixtureReport.scope.normalizedFixtureInputOnly, true);
  assert.equal(Object.hasOwn(fixtureReport.scope, 'blockBoundRpcObservation'), false);

  const liveReport = verifyApprovePostcheck(input, input.expected, { observationSource: 'sepolia-rpc-block-bound' });
  assert.equal(liveReport.verified, true);
  assert.equal(liveReport.scope.normalizedFixtureInputOnly, false);
  assert.equal(liveReport.scope.blockBoundRpcObservation, true);
  assert.equal(liveReport.scope.abiSourceMatched, true);
});

test('verifyApprovePostcheck rejects any other options value with code OPTIONS', () => {
  const input = approveEnvelope();
  for (const options of [
    { observationSource: 'other' },
    { observationSource: 'sepolia-rpc-block-bound', extra: true },
    {},
    { other: true },
    null,
    'sepolia-rpc-block-bound',
    42
  ]) {
    assert.throws(() => verifyApprovePostcheck(input, input.expected, options), { code: 'OPTIONS' }, JSON.stringify(options));
  }
});

// =====================================================================
// Regression: the original postBrickkenPrepare is unchanged
// =====================================================================

test('postBrickkenPrepare (the original caller) still posts to the fixed prepare-transactions URL', async () => {
  let observed;
  const fetchImpl = async (url, options) => { observed = { url, options }; return new Response('{}', { status: 200 }); };
  const body = await postBrickkenPrepare({ credential: SECRET, body: { method: 'approve' }, fetchImpl });
  assert.equal(observed.url, BRICKKEN_PREPARE_URL);
  assert.equal(body, '{}');
});
