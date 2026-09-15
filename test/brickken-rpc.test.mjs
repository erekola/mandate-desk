import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SEPOLIA_CHAIN_ID,
  SEPOLIA_RPC_ENDPOINTS,
  SepoliaRpc,
  SepoliaRpcError,
  blockRef,
  toPostcheckReceipt,
  compareBlockAcrossRpcs,
  finalityAcrossRpcs
} from '../src/brickken-rpc.mjs';

const HASH_A = '0x' + '11'.repeat(32);
const HASH_B = '0x' + '22'.repeat(32);
const ADDR_A = '0x' + 'aa'.repeat(20);
const ADDR_B = '0x' + 'bb'.repeat(20);
// 4-byte selector + one 32-byte address-shaped word (24 zero hex chars + 40 hex address chars).
const REVERT_DATA = '0x118cdaa7' + '0'.repeat(24) + 'aa'.repeat(20);

function jsonResponse(body, status = 200, headers = { 'content-type': 'application/json' }) {
  return new Response(JSON.stringify(body), { status, headers });
}

function fakeFetch(handler) {
  const calls = [];
  const impl = async (url, options) => {
    const parsedBody = JSON.parse(options.body);
    calls.push({ url, options, parsedBody });
    return handler(parsedBody, url, options);
  };
  impl.calls = calls;
  return impl;
}

function rpcFor(handler, overrides = {}) {
  return new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl: fakeFetch(handler), ...overrides });
}

function okResult(request, result) {
  return jsonResponse({ jsonrpc: '2.0', id: request.id, result });
}

function errResult(request, error) {
  // thirdweb-shaped ordering: error before id and jsonrpc, to prove key order is irrelevant.
  return jsonResponse({ error, id: request.id, jsonrpc: '2.0' });
}

test('endpoint allowlist: constructor accepts only the two fixed URLs', () => {
  assert.doesNotThrow(() => new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl: async () => {} }));
  assert.doesNotThrow(() => new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.secondary, fetchImpl: async () => {} }));
  for (const bad of ['https://example.invalid/', SEPOLIA_RPC_ENDPOINTS.primary + '/', '', undefined, null, 1]) {
    assert.throws(() => new SepoliaRpc({ endpoint: bad, fetchImpl: async () => {} }),
      error => error instanceof SepoliaRpcError && error.code === 'ENDPOINT_DENIED' && error.method === null);
  }
  const primary = new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl: async () => {} });
  const secondary = new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.secondary, fetchImpl: async () => {} });
  assert.equal(primary.endpointName, 'primary');
  assert.equal(secondary.endpointName, 'secondary');
  assert.equal(SEPOLIA_CHAIN_ID, '11155111');
});

test('constructor validates timeoutMs and maxResponseBytes bounds', () => {
  for (const timeoutMs of [0, -1, 60001, 1.5, Infinity, NaN]) {
    assert.throws(() => new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl: async () => {}, timeoutMs }),
      { code: 'INPUT_INVALID' });
  }
  for (const maxResponseBytes of [0, -1, 8_000_001, 1.5]) {
    assert.throws(() => new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl: async () => {}, maxResponseBytes }),
      { code: 'INPUT_INVALID' });
  }
  assert.doesNotThrow(() => new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl: async () => {}, timeoutMs: 1, maxResponseBytes: 1 }));
});

test('request shape details are exactly as specified, including a per-instance incrementing id', async () => {
  const handler = fakeFetch((request) => okResult(request, '0x1'));
  const rpc = new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.secondary, fetchImpl: handler });
  await rpc.blockNumber();
  await rpc.blockNumber();
  assert.equal(handler.calls.length, 2);
  const [first, second] = handler.calls;
  assert.equal(first.url, SEPOLIA_RPC_ENDPOINTS.secondary);
  assert.equal(first.options.method, 'POST');
  assert.equal(first.options.redirect, 'error');
  assert.equal(first.options.credentials, 'omit');
  assert.equal(first.options.referrerPolicy, 'no-referrer');
  assert.deepEqual(Object.keys(first.options.headers).sort(), ['accept', 'content-type']);
  assert.equal(first.options.headers.accept, 'application/json');
  assert.equal(first.options.headers['content-type'], 'application/json');
  assert.equal(first.parsedBody.jsonrpc, '2.0');
  assert.equal(first.parsedBody.method, 'eth_blockNumber');
  assert.deepEqual(first.parsedBody.params, []);
  assert.equal(typeof first.parsedBody.id, 'number');
  assert.equal(typeof second.parsedBody.id, 'number');
  assert.notEqual(first.parsedBody.id, second.parsedBody.id);
  assert.equal(first.options.signal instanceof AbortSignal, true);
});

test('id mismatch and missing jsonrpc field are rejected as RESPONSE_INVALID', async () => {
  const mismatched = rpcFor((request) => jsonResponse({ jsonrpc: '2.0', id: request.id + 1, result: '0x1' }));
  await assert.rejects(mismatched.blockNumber(), { code: 'RESPONSE_INVALID', method: 'eth_blockNumber' });

  const noJsonrpc = rpcFor((request) => jsonResponse({ id: request.id, result: '0x1' }));
  await assert.rejects(noJsonrpc.blockNumber(), { code: 'RESPONSE_INVALID' });

  const wrongJsonrpc = rpcFor((request) => jsonResponse({ jsonrpc: '1.0', id: request.id, result: '0x1' }));
  await assert.rejects(wrongJsonrpc.blockNumber(), { code: 'RESPONSE_INVALID' });

  const bothResultAndError = rpcFor((request) => jsonResponse({ jsonrpc: '2.0', id: request.id, result: '0x1', error: { code: -1, message: 'x' } }));
  await assert.rejects(bothResultAndError.blockNumber(), { code: 'RESPONSE_INVALID' });

  const neither = rpcFor((request) => jsonResponse({ jsonrpc: '2.0', id: request.id }));
  await assert.rejects(neither.blockNumber(), { code: 'RESPONSE_INVALID' });

  // key order must not matter: error before id and jsonrpc (thirdweb-shaped).
  const reordered = rpcFor((request) => errResult(request, { code: 3, message: 'execution reverted', data: null }));
  await assert.rejects(reordered.blockNumber(), { code: 'RPC_ERROR' });
});

test('HTTP 429 and 500 are classified without touching the body', async () => {
  let bodyTouched = false;
  const make = status => rpcFor(() => {
    const response = { status, redirected: false, url: SEPOLIA_RPC_ENDPOINTS.primary };
    Object.defineProperty(response, 'body', { get() { bodyTouched = true; throw new Error('must not read'); } });
    Object.defineProperty(response, 'headers', { get() { throw new Error('must not read'); } });
    return response;
  });
  await assert.rejects(make(429).blockNumber(), { code: 'HTTP_429' });
  assert.equal(bodyTouched, false);
  await assert.rejects(make(500).blockNumber(), { code: 'HTTP_REJECTED' });
  assert.equal(bodyTouched, false);
});

test('oversized body is rejected via declared content-length and via streaming', async () => {
  const declared = rpcFor(() => ({
    status: 200, redirected: false, url: SEPOLIA_RPC_ENDPOINTS.primary,
    headers: { get: name => name === 'content-length' ? '999999' : null },
    body: null
  }), { maxResponseBytes: 10 });
  await assert.rejects(declared.blockNumber(), { code: 'RESPONSE_TOO_LARGE' });

  const streamed = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(8));
      controller.enqueue(new Uint8Array(8));
      controller.close();
    }
  });
  const streaming = rpcFor(() => ({
    status: 200, redirected: false, url: SEPOLIA_RPC_ENDPOINTS.primary,
    headers: { get: () => null }, body: streamed
  }), { maxResponseBytes: 10 });
  await assert.rejects(streaming.blockNumber(), { code: 'RESPONSE_TOO_LARGE' });
});

test('timeout aborts the owned request without retrying, and network failure maps cleanly', async () => {
  let signal;
  const hangingFetch = async (_url, options) => { signal = options.signal; return await new Promise(() => {}); };
  const hanging = new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl: hangingFetch, timeoutMs: 10 });
  await assert.rejects(hanging.blockNumber(), { code: 'RPC_TIMEOUT' });
  assert.equal(signal.aborted, true);

  const networkFailure = new SepoliaRpc({
    endpoint: SEPOLIA_RPC_ENDPOINTS.primary,
    fetchImpl: async () => { throw new Error('network sentinel'); }
  });
  await assert.rejects(networkFailure.blockNumber(), error => {
    assert.equal(error.code, 'NETWORK_FAILED');
    assert.equal(error.message, 'NETWORK_FAILED');
    assert.equal(error.message.includes('sentinel'), false);
    return true;
  });
});

test('redirected response is rejected even when HTTP status is 200', async () => {
  const rpc = rpcFor(() => ({
    status: 200, redirected: true, url: SEPOLIA_RPC_ENDPOINTS.primary,
    headers: { get: () => null }, body: new Response('{}').body
  }));
  await assert.rejects(rpc.blockNumber(), { code: 'REDIRECT_REJECTED' });

  const differingUrl = rpcFor(() => ({
    status: 200, redirected: false, url: 'https://example.invalid/',
    headers: { get: () => null }, body: new Response('{}').body
  }));
  await assert.rejects(differingUrl.blockNumber(), { code: 'REDIRECT_REJECTED' });
});

test('quantity, data, address and hash normalization, including uppercase hex', async () => {
  const rpc = rpcFor((request) => okResult(request, '0xFF'));
  assert.equal(await rpc.blockNumber(), '255');

  const balanceRpc = rpcFor((request) => okResult(request, '0x0'));
  assert.equal(await balanceRpc.getBalance(ADDR_A, 'latest'), '0');

  const codeRpc = rpcFor((request) => okResult(request, '0xAB01'));
  assert.equal(await codeRpc.getCode(ADDR_A, 'latest'), '0xab01');

  const upperAddress = ADDR_A.toUpperCase().replace('0X', '0x');
  const addressHandler = fakeFetch((request) => okResult(request, '0x0'));
  const echoAddress = new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl: addressHandler });
  await echoAddress.getTransactionCount(upperAddress, 'latest');
  assert.equal(addressHandler.calls[0].parsedBody.params[0], ADDR_A);

  const upperHash = HASH_A.toUpperCase().replace('0X', '0x');
  const hashHandler = fakeFetch((request) => okResult(request, null));
  const echoHash = new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl: hashHandler });
  await echoHash.getTransactionByHash(upperHash);
  assert.equal(hashHandler.calls[0].parsedBody.params[0], HASH_A);

  for (const bad of ['0x', '0xzz', 'ff', '0x' + '1'.repeat(65)]) {
    const badRpc = rpcFor((request) => okResult(request, bad));
    await assert.rejects(badRpc.blockNumber(), { code: 'RESPONSE_INVALID' });
  }
});

test('caller input validation uses INPUT_INVALID and never reaches the network', async () => {
  let requested = false;
  const rpc = rpcFor(() => { requested = true; return okResult({ id: 1 }, '0x0'); });
  await assert.rejects(rpc.getBalance('not-an-address', 'latest'), { code: 'INPUT_INVALID' });
  await assert.rejects(rpc.getTransactionByHash('not-a-hash'), { code: 'INPUT_INVALID' });
  await assert.rejects(rpc.sendRawTransaction('0xabc'), { code: 'INPUT_INVALID' });
  await assert.rejects(rpc.sendRawTransaction('not-hex'), { code: 'INPUT_INVALID' });
  await assert.rejects(rpc.call({ to: ADDR_A, data: '0x', value: '0' }, 'latest'), { code: 'INPUT_INVALID' });
  await assert.rejects(rpc.call({ data: '0x' }, 'latest'), { code: 'INPUT_INVALID' });
  assert.equal(requested, false);
});

test('blockRef formats every accepted shape and rejects everything else', () => {
  assert.equal(blockRef('latest'), 'latest');
  assert.equal(blockRef('pending'), 'pending');
  assert.equal(blockRef('safe'), 'safe');
  assert.equal(blockRef('finalized'), 'finalized');
  assert.equal(blockRef({ blockNumber: '0' }), '0x0');
  assert.equal(blockRef({ blockNumber: '255' }), '0xff');
  assert.equal(blockRef({ blockNumber: '4370000' }), '0x' + (4370000).toString(16));
  const byHash = blockRef({ blockHash: HASH_A.toUpperCase().replace('0X', '0x') });
  assert.deepEqual(byHash, { blockHash: HASH_A, requireCanonical: true });

  for (const bad of ['earliest', 42, { blockNumber: '01' }, { blockNumber: 1 }, { blockNumber: '-1' },
    { blockHash: '0xabc' }, { blockNumber: '1', blockHash: HASH_A }, {}, null, undefined, []]) {
    assert.throws(() => blockRef(bad), error => error instanceof SepoliaRpcError &&
      error.code === 'BLOCK_REF_INVALID' && error.method === null);
  }
});

test('getBlock rejects pending, dispatches by hash vs number, and handles null', async () => {
  const rpc = rpcFor(() => { throw new Error('must not request'); });
  await assert.rejects(rpc.getBlock('pending'), { code: 'INPUT_INVALID' });

  const byNumber = rpcFor((request) => {
    assert.equal(request.method, 'eth_getBlockByNumber');
    assert.deepEqual(request.params, ['latest', false]);
    return okResult(request, null);
  });
  assert.equal(await byNumber.getBlock('latest'), null);

  const byHash = rpcFor((request) => {
    assert.equal(request.method, 'eth_getBlockByHash');
    assert.deepEqual(request.params, [HASH_A, false]);
    return okResult(request, {
      number: '0x64', hash: HASH_A, parentHash: HASH_B, timestamp: '0x5', baseFeePerGas: '0x3b9aca00'
    });
  });
  const block = await byHash.getBlock({ blockHash: HASH_A });
  assert.deepEqual(block, { number: '100', hash: HASH_A, parentHash: HASH_B, timestamp: '5', baseFeePerGas: '1000000000' });
  assert.throws(() => { block.number = 'x'; });

  const missingBaseFee = rpcFor((request) => okResult(request, { number: '0x1', hash: HASH_A, parentHash: HASH_B, timestamp: '0x1' }));
  await assert.rejects(missingBaseFee.getBlock('latest'), { code: 'RESPONSE_INVALID' });
});

test('call: success, execution revert with data, and non-revert RPC error', async () => {
  const success = rpcFor((request) => {
    assert.equal(request.method, 'eth_call');
    assert.deepEqual(request.params[0], { to: ADDR_A, data: '0x01' });
    assert.equal(request.params[1], 'latest');
    return okResult(request, '0x2a');
  });
  assert.deepEqual(await success.call({ to: ADDR_A, data: '0x01' }, 'latest'), { ok: true, returnData: '0x2a' });

  const revertByCode = rpcFor((request) => errResult(request, { code: 3, message: 'execution reverted', data: REVERT_DATA }));
  assert.deepEqual(await revertByCode.call({ from: ADDR_B, to: ADDR_A, data: '0x' }, 'latest'),
    { ok: false, revertData: REVERT_DATA });

  const revertByMessage = rpcFor((request) => errResult(request, { code: -32000, message: 'reverted: custom reason', data: null }));
  assert.deepEqual(await revertByMessage.call({ to: ADDR_A, data: '0x' }, 'latest'), { ok: false, revertData: null });

  const otherError = rpcFor((request) => errResult(request, { code: -32602, message: 'invalid params' }));
  await assert.rejects(otherError.call({ to: ADDR_A, data: '0x' }, 'latest'), { code: 'RPC_ERROR' });
});

test('estimateGas: success, revert throws ESTIMATE_REVERTED, other errors throw RPC_ERROR, default ref is latest', async () => {
  const success = rpcFor((request) => {
    assert.equal(request.params[1], 'latest');
    return okResult(request, '0x5208');
  });
  assert.equal(await success.estimateGas({ to: ADDR_A, data: '0x' }), '21000');

  const revert = rpcFor((request) => errResult(request, { code: 3, message: 'execution reverted', data: REVERT_DATA }));
  await assert.rejects(revert.estimateGas({ to: ADDR_A, data: '0x' }), { code: 'ESTIMATE_REVERTED' });

  const other = rpcFor((request) => errResult(request, { code: -32602, message: 'invalid params' }));
  await assert.rejects(other.estimateGas({ to: ADDR_A, data: '0x' }), { code: 'RPC_ERROR' });
});

test('getTransactionByHash: pending transaction and type rejection', async () => {
  const txFixture = {
    hash: HASH_A, from: ADDR_A, to: ADDR_B, nonce: '0x1', value: '0x0', input: '0xabcd',
    type: '0x2', chainId: '0x' + BigInt(SEPOLIA_CHAIN_ID).toString(16), gas: '0x5208',
    maxFeePerGas: '0x3b9aca00', maxPriorityFeePerGas: '0x3b9aca00', blockNumber: null, blockHash: null
  };
  const pending = rpcFor((request) => okResult(request, txFixture));
  const result = await pending.getTransactionByHash(HASH_A);
  assert.equal(result.blockNumber, null);
  assert.equal(result.blockHash, null);
  assert.equal(result.data, '0xabcd');
  assert.equal(result.gasLimit, '21000');
  assert.equal(result.type, 2);

  const wrongType = rpcFor((request) => okResult(request, { ...txFixture, type: '0x1' }));
  await assert.rejects(wrongType.getTransactionByHash(HASH_A), { code: 'RESPONSE_INVALID' });

  const contractCreation = rpcFor((request) => okResult(request, { ...txFixture, to: null, blockNumber: '0x1', blockHash: HASH_B }));
  await assert.rejects(contractCreation.getTransactionByHash(HASH_A), { code: 'RESPONSE_INVALID' });

  const notFound = rpcFor((request) => okResult(request, null));
  assert.equal(await notFound.getTransactionByHash(HASH_A), null);
});

test('getTransactionReceipt: normalization and toPostcheckReceipt key projection', async () => {
  const logFixture = {
    address: ADDR_A, topics: [HASH_A, HASH_B], data: '0xAB', transactionHash: HASH_A,
    blockNumber: '0x64', blockHash: HASH_B, logIndex: '0x0'
  };
  const receiptFixture = {
    transactionHash: HASH_A, status: '0x1', from: ADDR_A, to: ADDR_B, blockNumber: '0x64',
    blockHash: HASH_B, gasUsed: '0x5208', effectiveGasPrice: '0x3b9aca00', logs: [logFixture]
  };
  const rpc = rpcFor((request) => okResult(request, receiptFixture));
  const receipt = await rpc.getTransactionReceipt(HASH_A);
  assert.equal(receipt.status, 1);
  assert.equal(receipt.logs[0].data, '0xab');
  assert.equal(receipt.logs[0].removed, false);
  assert.equal(receipt.logs[0].blockNumber, '100');
  assert.equal(receipt.logs[0].logIndex, '0');

  const postcheckShape = toPostcheckReceipt(receipt);
  assert.deepEqual(Object.keys(postcheckShape).sort(),
    ['blockHash', 'blockNumber', 'from', 'logs', 'status', 'to', 'transactionHash'].sort());
  assert.deepEqual(Object.keys(postcheckShape.logs[0]).sort(),
    ['address', 'blockHash', 'blockNumber', 'data', 'logIndex', 'removed', 'topics', 'transactionHash'].sort());
  assert.equal(Object.hasOwn(postcheckShape, 'gasUsed'), false);
  assert.equal(Object.hasOwn(postcheckShape, 'effectiveGasPrice'), false);

  const explicitRemoved = rpcFor((request) => okResult(request, {
    ...receiptFixture, logs: [{ ...logFixture, removed: true }]
  }));
  const withRemoved = await explicitRemoved.getTransactionReceipt(HASH_A);
  assert.equal(withRemoved.logs[0].removed, true);

  const badStatus = rpcFor((request) => okResult(request, { ...receiptFixture, status: '0x2' }));
  await assert.rejects(badStatus.getTransactionReceipt(HASH_A), { code: 'RESPONSE_INVALID' });
});

test('every sendRawTransaction error class is classified from the sanitized message', async () => {
  const cases = [
    ['already known', 'ALREADY_KNOWN'],
    ['Known transaction hash abc', 'ALREADY_KNOWN'],
    ['nonce too low', 'NONCE_TOO_LOW'],
    ['replacement transaction underpriced', 'REPLACEMENT_UNDERPRICED'],
    ['insufficient funds for gas * price + value', 'INSUFFICIENT_FUNDS'],
    ['max fee per gas less than block base fee', 'FEE_TOO_LOW'],
    ['fee cap less than block base fee', 'FEE_TOO_LOW'],
    ['transaction underpriced', 'FEE_TOO_LOW'],
    ['some unrelated provider text', 'RPC_REJECTED']
  ];
  for (const [message, code] of cases) {
    const rpc = rpcFor((request) => errResult(request, { code: -32000, message }));
    await assert.rejects(rpc.sendRawTransaction('0x' + 'ab'.repeat(10)), { code }, message);
  }
  const success = rpcFor((request) => okResult(request, HASH_A.toUpperCase().replace('0X', '0x')));
  assert.equal(await success.sendRawTransaction('0x' + 'ab'.repeat(10)), HASH_A);
});

test('compareBlockAcrossRpcs: agree, disagree and null', async () => {
  const primary = new SepoliaRpc({
    endpoint: SEPOLIA_RPC_ENDPOINTS.primary,
    fetchImpl: fakeFetch((request) => okResult(request, { number: '0x64', hash: HASH_A, parentHash: HASH_B, timestamp: '0x1', baseFeePerGas: '0x1' }))
  });
  const secondaryAgree = new SepoliaRpc({
    endpoint: SEPOLIA_RPC_ENDPOINTS.secondary,
    fetchImpl: fakeFetch((request) => okResult(request, { number: '0x64', hash: HASH_A, parentHash: HASH_B, timestamp: '0x1', baseFeePerGas: '0x1' }))
  });
  const agreeResult = await compareBlockAcrossRpcs([primary, secondaryAgree], '100');
  assert.deepEqual(agreeResult, { agreed: true, blockNumber: '100', hashes: [HASH_A, HASH_A] });

  const secondaryDisagree = new SepoliaRpc({
    endpoint: SEPOLIA_RPC_ENDPOINTS.secondary,
    fetchImpl: fakeFetch((request) => okResult(request, { number: '0x64', hash: HASH_B, parentHash: HASH_A, timestamp: '0x1', baseFeePerGas: '0x1' }))
  });
  const disagreeResult = await compareBlockAcrossRpcs([primary, secondaryDisagree], '100');
  assert.equal(disagreeResult.agreed, false);
  assert.deepEqual(disagreeResult.hashes, [HASH_A, HASH_B]);

  const secondaryNull = new SepoliaRpc({
    endpoint: SEPOLIA_RPC_ENDPOINTS.secondary,
    fetchImpl: fakeFetch((request) => okResult(request, null))
  });
  const nullResult = await compareBlockAcrossRpcs([primary, secondaryNull], '100');
  assert.equal(nullResult.agreed, false);
  assert.deepEqual(nullResult.hashes, [HASH_A, null]);

  await assert.rejects(compareBlockAcrossRpcs([primary], '100'), { code: 'INPUT_INVALID' });
  await assert.rejects(compareBlockAcrossRpcs([primary, primary], '100'), { code: 'INPUT_INVALID' });
});

test('finalityAcrossRpcs: true, false for lagging finality, false for hash mismatch', async () => {
  function rpcWith(endpoint, finalizedNumber, finalizedHash, hashAtNumber) {
    return new SepoliaRpc({
      endpoint, fetchImpl: fakeFetch((request) => {
        if (request.params[0] === 'finalized') {
          return okResult(request, { number: finalizedNumber, hash: finalizedHash, parentHash: HASH_B, timestamp: '0x1', baseFeePerGas: '0x1' });
        }
        return okResult(request, hashAtNumber === null ? null : { number: '0x64', hash: hashAtNumber, parentHash: HASH_B, timestamp: '0x1', baseFeePerGas: '0x1' });
      })
    });
  }

  const finalizedPrimary = rpcWith(SEPOLIA_RPC_ENDPOINTS.primary, '0xc8', HASH_B, HASH_A);
  const finalizedSecondary = rpcWith(SEPOLIA_RPC_ENDPOINTS.secondary, '0xc8', HASH_B, HASH_A);
  const trueResult = await finalityAcrossRpcs([finalizedPrimary, finalizedSecondary], '100', HASH_A);
  assert.equal(trueResult.finalized, true);
  assert.equal(trueResult.observations.length, 2);
  assert.equal(trueResult.observations[0].endpointName, 'primary');
  assert.equal(trueResult.observations[0].finalizedNumber, '200');

  const laggingPrimary = rpcWith(SEPOLIA_RPC_ENDPOINTS.primary, '0x32', HASH_B, HASH_A);
  const laggingResult = await finalityAcrossRpcs([laggingPrimary, finalizedSecondary], '100', HASH_A);
  assert.equal(laggingResult.finalized, false);

  const mismatchPrimary = rpcWith(SEPOLIA_RPC_ENDPOINTS.primary, '0xc8', HASH_B, HASH_B);
  const mismatchResult = await finalityAcrossRpcs([mismatchPrimary, finalizedSecondary], '100', HASH_A);
  assert.equal(mismatchResult.finalized, false);

  await assert.rejects(finalityAcrossRpcs([finalizedPrimary], '100', HASH_A), { code: 'INPUT_INVALID' });
});

// Measured on 2026-09-14: Node fetch reports https://ethereum-sepolia-rpc.publicnode.com/
// for a request to the same origin without a path, so the normalized URL is the identity.
test('a response URL normalized with a trailing slash is accepted and a different host is rejected', async () => {
  const reply = url => async () => ({
    status: 200, redirected: false, url, headers: { get: () => null },
    body: new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0xaa36a7' })).body
  });
  const accepted = new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl: reply('https://ethereum-sepolia-rpc.publicnode.com/') });
  assert.equal(await accepted.chainId(), '11155111');
  const redirected = new SepoliaRpc({ endpoint: SEPOLIA_RPC_ENDPOINTS.primary, fetchImpl: reply('https://example.invalid/') });
  await assert.rejects(redirected.chainId(), { code: 'REDIRECT_REJECTED' });
});
