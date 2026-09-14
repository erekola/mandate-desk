import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BRICKKEN_PREPARE_URL,
  BrickkenHttpError,
  postBrickkenPrepare
} from '../src/brickken-http.mjs';

const SECRET = 'fixture-api-key-secret-sentinel';
const BODY = { method: 'approve', signerAddress: '0x' + '11'.repeat(20) };

test('caller uses only the fixed official sandbox POST route and injected in-memory API key', async () => {
  let observed;
  const fetchImpl = async (url, options) => {
    observed = { url, options };
    return new Response('{"transactions":[],"txId":"fixture"}', {
      status: 200,
      headers: { 'content-type': 'application/json' }
    });
  };
  const body = await postBrickkenPrepare({ credential: SECRET, body: BODY, fetchImpl });
  assert.equal(body, '{"transactions":[],"txId":"fixture"}');
  assert.equal(observed.url, 'https://api.sandbox.brickken.com/prepare-transactions');
  assert.equal(observed.url, BRICKKEN_PREPARE_URL);
  assert.equal(observed.options.method, 'POST');
  assert.equal(observed.options.redirect, 'error');
  assert.equal(observed.options.credentials, 'omit');
  assert.equal(observed.options.referrerPolicy, 'no-referrer');
  assert.equal(observed.options.headers['x-api-key'], SECRET);
  assert.equal(Object.hasOwn(observed.options.headers, 'x-payment'), false);
  assert.deepEqual(JSON.parse(observed.options.body), BODY);
  assert.equal(observed.options.signal instanceof AbortSignal, true);
});

test('every non-200 status is classified before body access or parsing, including 402 and 403', async () => {
  const cases = new Map([
    [201, 'HTTP_REJECTED'], [204, 'HTTP_REJECTED'], [301, 'HTTP_REJECTED'],
    [400, 'HTTP_REJECTED'], [401, 'AUTHORIZATION_DENIED'], [402, 'PAYMENT_REQUIRED'],
    [403, 'AUTHORIZATION_DENIED'], [404, 'HTTP_REJECTED'], [429, 'HTTP_REJECTED'],
    [500, 'HTTP_REJECTED'], [599, 'HTTP_REJECTED']
  ]);
  for (const [status, code] of cases) {
    let bodyAccessed = false;
    const response = { status, redirected: false, url: BRICKKEN_PREPARE_URL };
    Object.defineProperty(response, 'body', {
      get() { bodyAccessed = true; throw new Error('secret response sentinel'); }
    });
    await assert.rejects(
      postBrickkenPrepare({ credential: SECRET, body: BODY, fetchImpl: async () => response }),
      error => {
        assert.equal(error instanceof BrickkenHttpError, true);
        assert.equal(error.code, code);
        assert.equal(error.status, status);
        assert.equal(error.message.includes('secret'), false);
        return true;
      }
    );
    assert.equal(bodyAccessed, false, String(status));
  }
});

test('caller never parses a successful body and the strict prepare validator owns JSON parsing', async () => {
  const malformed = '{secret-sentinel';
  const value = await postBrickkenPrepare({
    credential: SECRET,
    body: BODY,
    fetchImpl: async () => new Response(malformed, { status: 200 })
  });
  assert.equal(value, malformed);
});

test('response bytes are bounded by declared length and while streaming', async () => {
  let bodyAccessed = false;
  const declared = {
    status: 200,
    redirected: false,
    url: BRICKKEN_PREPARE_URL,
    headers: { get: name => name === 'content-length' ? '11' : null }
  };
  Object.defineProperty(declared, 'body', {
    get() { bodyAccessed = true; throw new Error('must not read'); }
  });
  await assert.rejects(postBrickkenPrepare({
    credential: SECRET, body: BODY, fetchImpl: async () => declared,
    maxResponseBytes: 10
  }), { code: 'RESPONSE_TOO_LARGE' });
  assert.equal(bodyAccessed, false);

  const streamed = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(8));
      controller.enqueue(new Uint8Array(8));
      controller.close();
    }
  });
  await assert.rejects(postBrickkenPrepare({
    credential: SECRET, body: BODY,
    fetchImpl: async () => ({ status: 200, redirected: false,
      url: BRICKKEN_PREPARE_URL, headers: { get: () => null }, body: streamed }),
    maxResponseBytes: 10
  }), { code: 'RESPONSE_TOO_LARGE' });
});

test('timeout aborts the owned request without exposing credentials or network errors', async () => {
  let signal;
  await assert.rejects(postBrickkenPrepare({
    credential: SECRET,
    body: BODY,
    timeoutMs: 10,
    fetchImpl: async (_url, options) => {
      signal = options.signal;
      return await new Promise(() => {});
    }
  }), error => {
    assert.equal(error.code, 'HTTP_TIMEOUT');
    assert.equal(error.message.includes(SECRET), false);
    return true;
  });
  assert.equal(signal.aborted, true);
  await assert.rejects(postBrickkenPrepare({
    credential: SECRET,
    body: BODY,
    fetchImpl: async () => { throw new Error('network ' + SECRET); }
  }), error => {
    assert.equal(error.code, 'NETWORK_FAILED');
    assert.equal(error.message.includes(SECRET), false);
    return true;
  });
});

test('redirects, invalid UTF-8, missing streams and overlarge requests fail closed', async () => {
  await assert.rejects(postBrickkenPrepare({
    credential: SECRET, body: BODY,
    fetchImpl: async () => ({ status: 200, redirected: true, url: 'https://example.invalid/',
      headers: { get: () => null }, body: new Response('{}').body })
  }), { code: 'REDIRECT_REJECTED' });
  await assert.rejects(postBrickkenPrepare({
    credential: SECRET, body: BODY,
    fetchImpl: async () => ({ status: 200, redirected: false, url: BRICKKEN_PREPARE_URL,
      headers: { get: () => null }, body: null })
  }), { code: 'RESPONSE_STREAM_REQUIRED' });
  const invalidUtf8 = new ReadableStream({
    start(controller) { controller.enqueue(Uint8Array.from([0xc3, 0x28])); controller.close(); }
  });
  await assert.rejects(postBrickkenPrepare({
    credential: SECRET, body: BODY,
    fetchImpl: async () => ({ status: 200, redirected: false, url: BRICKKEN_PREPARE_URL,
      headers: { get: () => null }, body: invalidUtf8 })
  }), { code: 'RESPONSE_READ_FAILED' });
  await assert.rejects(postBrickkenPrepare({
    credential: SECRET, body: { value: 'x'.repeat(100) }, maxRequestBytes: 20,
    fetchImpl: async () => new Response('{}')
  }), { code: 'REQUEST_TOO_LARGE' });
  for (const bad of ['', 'line\nbreak', null, 1]) {
    await assert.rejects(postBrickkenPrepare({ credential: bad, body: BODY,
      fetchImpl: async () => new Response('{}') }), { code: 'CREDENTIAL_INVALID' });
  }
});
