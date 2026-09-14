import test from 'node:test';
import assert from 'node:assert/strict';
import { buildBrickkenRead, readBrickken, classifyBrickkenFailure, getBrickkenReadFailureDetails } from '../src/brickken-read.mjs';
const principal = '0x1F5ED27Aef8367bc8eA936Ec562b776A1399E5D4';
const agent = '0x18Ff8b19E9E9cc35c7F10b1c690BB84D56CC9442';
const executorAddress = '0x' + 'a'.repeat(40); // fixture, not provisioned
const asset = '0x' + 'b'.repeat(40); // fixture, not a real token claim
const input = { kind: 'executor', chainId: '11155111', principal, executorAddress };
const can = { kind: 'can-execute', chainId: '11155111', principal, agent, asset, amount: '30000000' };
const apiKey = 'TEST-ONLY-NOT-A-CREDENTIAL';
const action = '0x23b872dd' + '0'.repeat(56);
const registry = '0xD68E1bb972cA4EF7F5764FBf6d685a6DfC26778e';
const executor = () => ({ data: { executorAddress, principal, owner: principal, agentMandateAddress: registry,
  selector: '0x23b872dd', action, spec: { supported: true, hasAmount: true, amountIndex: 2 } } });
const execution = () => ({ data: { principal, agent, asset, amount: can.amount, selector: '0x23b872dd', action, allowed: false,
  checks: { mandateExists: true, assetMatches: true, withinValidityWindow: true, notRevoked: true, actionEnabled: true,
    agentNotFrozen: true, withinTransactionCap: false, withinCumulativeCap: true } } });
const response = body => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
const read = (request, body) => readBrickken(request, { apiKey, fetchImpl: async () => response(body) });

test('Brickken reader uses only fixed sandbox GET and returns typed executor evidence', async () => {
  let calls = 0;
  const result = await readBrickken(input, { apiKey, fetchImpl: async (url, options) => {
    calls++; const parsed = new URL(url);
    assert.equal(parsed.origin, 'https://api.sandbox.brickken.com'); assert.equal(parsed.pathname, '/rams/executor-action');
    assert.equal(url.includes(apiKey), false);
    assert.equal(parsed.searchParams.get('executorAddress'), executorAddress);
    assert.equal(options.method, 'GET'); assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit');
    assert.equal(options.headers['x-api-key'], apiKey); assert.equal(Object.hasOwn(options, 'body'), false);
    return response({ ...executor(), keyEcho: apiKey });
  } });
  assert.equal(calls, 1); assert.equal(result.valueExtractionReady, true); assert.equal(result.recorderRoleVerified, false);
  assert.equal(JSON.stringify(result).includes(apiKey), false);
});
test('Brickken input rejects chain, arbitrary route, unknown query, default executor and bad amount before network', async () => {
  const invalid = [{ ...input, chainId: '1' }, { ...input, kind: 'send' }, { ...input, url: 'https://other.invalid' },
    { ...input, executorAddress: '0xc81949Cf5b52BDc7890Fd5040A9Cd0cdb4B59952' },
    { ...input, executorAddress: principal }, { ...can, amount: '-1' }, { ...can, amount: '1.5' },
    { ...can, amount: (1n << 256n).toString() }, { ...can, asset: '0x' + '0'.repeat(40) }, { ...can, agent: principal }];
  let calls = 0;
  for (const item of invalid) await assert.rejects(readBrickken(item, { apiKey, fetchImpl: async () => { calls++; } }));
  assert.equal(calls, 0);
});
test('executor response binding rejects another principal, owner, registry, executor or malformed spec', async () => {
  for (const field of ['principal', 'owner', 'agentMandateAddress', 'executorAddress']) {
    const body = executor(); body.data[field] = asset; await assert.rejects(read(input, body), { code: 'RESPONSE_IDENTITY_MISMATCH' });
  }
  const body = executor(); body.data.spec.supported = 'true'; await assert.rejects(read(input, body), { code: 'RESPONSE_INVALID' });
  for (const spec of [{ supported: false, hasAmount: true, amountIndex: 2 }, { supported: true, hasAmount: false, amountIndex: 2 }, { supported: true, hasAmount: true, amountIndex: 0 }]) {
    const fixture = executor(); fixture.data.spec = spec; assert.equal((await read(input, fixture)).valueExtractionReady, false);
  }
});
test('can-execute preserves top-level denied result and does not claim a chain transaction', async () => {
  const body = execution(); const result = await read(can, body);
  assert.equal(result.allowed, false); assert.equal(result.transactionSent, false); assert.equal(result.independentRpcVerified, false);
  body.data.allowed = false; body.data.checks.withinTransactionCap = true;
  assert.equal((await read(can, body)).allowed, false);
  body.data.allowed = true; body.data.checks.withinTransactionCap = false;
  assert.equal((await read(can, body)).allowed, true);
  body.data.amount = '1'; await assert.rejects(read(can, body), { code: 'RESPONSE_INVALID' });
});
test('mandate summary is identity checked and explicitly incomplete', async () => {
  const request = { kind: 'mandate', chainId: '11155111', principal, agent };
  const body = { data: { chainId: '11155111', principal, agent, agentMandateAddress: registry, status: 'none', frozen: false, nonce: '0' } };
  assert.equal((await read(request, body)).completeMandateVerified, false);
  body.data.chainId = '1'; await assert.rejects(read(request, body), { code: 'RESPONSE_IDENTITY_MISMATCH' });
});
test('errors do not reveal server text, credentials or native exception content; no retries/payments', async () => {
  for (const status of [400, 401, 402, 403, 429, 500]) {
    let calls = 0;
    await assert.rejects(readBrickken(input, { apiKey, fetchImpl: async () => {
      calls++; return new Response(apiKey, { status });
    } }), error => { assert.equal(error.status, status); assert.equal(String(error).includes(apiKey), false); return true; });
    assert.equal(calls, 1);
  }
  await assert.rejects(readBrickken(input, { apiKey, fetchImpl: async () => { throw new Error(apiKey); } }), { code: 'READ_FAILED' });
  assert.equal(classifyBrickkenFailure(400, 'Unauthorized token symbol'), 'TOKEN_SCOPE_OR_REGISTRATION');
});
test('redirects, oversized streams, malformed JSON and wrong response types fail closed', async () => {
  for (const fixture of [new Response('', { status: 302 }), new Response('x'.repeat(65537)),
    new Response('{', { headers: { 'Content-Type': 'application/json' } }), new Response(JSON.stringify(executor()))]) {
    await assert.rejects(readBrickken(input, { apiKey, fetchImpl: async () => fixture }));
  }
  await assert.rejects(readBrickken(input, { apiKey, fetchImpl: async () => ({ redirected: true }) }), { code: 'REDIRECT_DENIED' });
  for (const bad of ['', 'a\r\nb', 'a b', 'ü', 'x'.repeat(4097)]) await assert.rejects(readBrickken(input, { apiKey: bad }), { code: 'KEY_INPUT_INVALID' });
  assert.equal(buildBrickkenRead(can).expected.amount, '30000000');
});
test('missing chain/registry echoes are explicit; contradictory echoes cannot become evidence', async () => {
  const result = await read(can, execution());
  assert.equal(result.requestedChainId, '11155111'); assert.equal(result.responseChainIdObserved, false);
  assert.equal(result.responseRegistryObserved, false); assert.equal(Object.hasOwn(result, 'chainId'), false);
  for (const extra of [{ chainId: '1' }, { agentMandateAddress: asset }]) {
    const body = execution(); Object.assign(body.data, extra);
    await assert.rejects(read(can, body), { code: 'RESPONSE_IDENTITY_MISMATCH' });
  }
});
test('stream byte limit is exact and redirect URL mismatch is rejected', async () => {
  const exactBody = JSON.stringify(executor());
  const exact = new Response(exactBody.padEnd(65536, ' '), { headers: { 'Content-Type': 'application/json' } });
  assert.equal((await readBrickken(input, { apiKey, fetchImpl: async () => exact })).valueExtractionReady, true);
  await assert.rejects(readBrickken(input, { apiKey, fetchImpl: async () => new Response('x'.repeat(65537)) }), { code: 'RESPONSE_TOO_LARGE' });
  await assert.rejects(readBrickken(input, { apiKey, fetchImpl: async () => ({ url: 'https://other.invalid', redirected: false }) }), { code: 'REDIRECT_DENIED' });
});
test('compliance binds exact identity reference and provider without echoing arbitrary reason text', async () => {
  const identityRef = '0x' + '1'.repeat(64);
  const request = { kind: 'compliance', chainId: '11155111', principal, identityRef };
  const body = { data: { principal, identityRef, complianceProviderAddress: '0xa90D2503D5D9b80ECC27856Ff76F892B8C02f278',
    eligible: true, reason: apiKey, reasonCode: 0, expiresAt: 0 } };
  const result = await read(request, body);
  assert.equal(result.eligible, true); assert.equal(JSON.stringify(result).includes(apiKey), false);
  body.data.identityRef = '0x' + '2'.repeat(64); await assert.rejects(read(request, body), { code: 'RESPONSE_IDENTITY_MISMATCH' });
  assert.throws(() => buildBrickkenRead({ ...request, identityRef: 'not-an-identity-ref' }), { code: 'IDENTITY_REF_INVALID' });
});

async function rejectedDetails(body, headers = { 'Content-Type': 'application/json' }) {
  let failure;
  await assert.rejects(readBrickken(input, { apiKey, fetchImpl: async () => new Response(
    typeof body === 'string' ? body : JSON.stringify(body), { status: 200, headers }
  ) }), error => { failure = error; return true; });
  return { failure, details: getBrickkenReadFailureDetails(failure) };
}

test('failure diagnostics classify transport shape without copying values, arbitrary keys or headers', async () => {
  const hostileKey = `untrusted-${apiKey}`;
  const nested = { data: { result: { data: executor().data, message: apiKey, [hostileKey]: apiKey } } };
  const { failure, details } = await rejectedDetails(nested);
  assert.equal(failure.code, 'RESPONSE_INVALID');
  assert.equal(failure.status, 0);
  assert.equal(details.stage, 'schema');
  assert.equal(details.httpStatus, 200);
  assert.equal(details.mediaTypeClass, 'json');
  assert.equal(details.jsonRootType, 'object');
  const result = details.shape.find(item => item.path === 'data.result');
  assert.equal(result.type, 'object');
  assert.equal(result.fields.data, 'object');
  assert.equal(result.fields.message, 'string');
  assert.equal(Object.hasOwn(result.fields, hostileKey), false);
  assert.equal(JSON.stringify(details).includes(apiKey), false);
  details.stage = 'changed-by-caller';
  assert.equal(getBrickkenReadFailureDetails(failure).stage, 'schema');
  assert.equal(getBrickkenReadFailureDetails(new Error('other')), undefined);
});

test('non-JSON and malformed JSON diagnostics expose only media class, byte count and root type', async () => {
  const html = await rejectedDetails(`<html>${apiKey}</html>`, { 'Content-Type': `text/html; secret=${apiKey}` });
  assert.deepEqual(html.details, {
    stage: 'header', httpStatus: 200, mediaTypeClass: 'html',
    bodyBytes: Buffer.byteLength(`<html>${apiKey}</html>`), jsonRootType: 'missing'
  });
  const malformed = await rejectedDetails(`{"message":"${apiKey}"`, { 'Content-Type': 'application/json' });
  assert.equal(malformed.details.stage, 'json');
  assert.equal(malformed.details.mediaTypeClass, 'json');
  assert.equal(malformed.details.jsonRootType, 'missing');
  assert.equal(JSON.stringify(malformed.details).includes(apiKey), false);
});

test('malformed direct payload and nested response diagnostics explain fixed field types', async () => {
  const invalidDirect = { ...executor().data, message: apiKey, [apiKey]: 'secret' };
  invalidDirect.spec = { ...invalidDirect.spec, supported: apiKey };
  const flat = await rejectedDetails(invalidDirect);
  assert.equal(flat.failure.code, 'RESPONSE_INVALID');
  const flatRoot = flat.details.shape.find(item => item.path === 'root');
  assert.equal(flatRoot.fields.executorAddress, 'string');
  assert.equal(flatRoot.fields.data, 'missing');
  assert.equal(flat.details.shape.find(item => item.path === 'root.spec').fields.supported, 'string');
  assert.equal(JSON.stringify(flat.details).includes(apiKey), false);

  const array = await rejectedDetails({ data: [{ principal: apiKey, nonce: null, [apiKey]: true }] });
  assert.equal(array.failure.code, 'RESPONSE_INVALID');
  assert.equal(array.details.shape.find(item => item.path === 'data').type, 'array');
  const first = array.details.shape.find(item => item.path === 'data[0]');
  assert.equal(first.fields.principal, 'string');
  assert.equal(first.fields.nonce, 'null');
  assert.equal(Object.hasOwn(first.fields, apiKey), false);
  assert.equal(JSON.stringify(array.details).includes(apiKey), false);
});

test('schema-stage diagnostics report wrong fixed field types without weakening validation', async () => {
  const body = executor();
  body.data.spec.supported = apiKey;
  body.data.message = apiKey;
  body.data[apiKey] = apiKey;
  const { failure, details } = await rejectedDetails(body);
  assert.equal(failure.code, 'RESPONSE_INVALID');
  const data = details.shape.find(item => item.path === 'data');
  const spec = details.shape.find(item => item.path === 'data.spec');
  assert.equal(data.fields.spec, 'object');
  assert.equal(data.fields.message, 'string');
  assert.equal(spec.fields.supported, 'string');
  assert.equal(spec.fields.hasAmount, 'boolean');
  assert.equal(spec.fields.amountIndex, 'number');
  assert.equal(JSON.stringify(details).includes(apiKey), false);
});

test('live direct payload and documented data envelope have identical validated observations', async () => {
  assert.deepEqual(await read(input, executor().data), await read(input, executor()));
  assert.deepEqual(await read(can, execution().data), await read(can, execution()));
  const wrongOwner = executor().data;
  wrongOwner.owner = asset;
  await assert.rejects(read(input, wrongOwner), { code: 'RESPONSE_IDENTITY_MISMATCH' });
  const wrongChain = { ...executor().data, chainId: '1' };
  await assert.rejects(read(input, wrongChain), { code: 'RESPONSE_IDENTITY_MISMATCH' });
  const wrongAmount = { ...execution().data, amount: '1' };
  await assert.rejects(read(can, wrongAmount), { code: 'RESPONSE_INVALID' });
});

test('malformed, mixed and competing envelopes never fall back to a valid-looking payload', async () => {
  const valid = executor().data;
  for (const body of [
    { ...valid, data: null }, { ...valid, data: valid }, { data: valid, principal },
    { data: valid, executorAddress: asset }, { data: [valid] },
    { result: valid }, { response: valid }, { data: { data: valid } },
    { ...valid, errors: {} }, { data: valid, error: null }, { data: { ...valid, error: null } }
  ]) await assert.rejects(read(input, body), { code: 'RESPONSE_INVALID' });
});
