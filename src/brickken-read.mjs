// Internal adapter scaffolding. GET only; no wallet, environment, file or logging access.
// Protocol source: docs.brickken.com/api-reference/endpoint/rams-{get-mandate,can-execute,executor-action}.
const ORIGIN = 'https://api.sandbox.brickken.com';
const CHAIN = '11155111';
const REGISTRY = '0xd68e1bb972ca4ef7f5764fbf6d685a6dfc26778e';
const PROVIDER = '0xa90d2503d5d9b80ecc27856ff76f892b8c02f278';
const PLATFORM_EXECUTOR = '0xc81949cf5b52bdc7890fd5040a9cd0cdb4b59952';
const SELECTOR = '0x23b872dd';
const ACTION = SELECTOR + '0'.repeat(56);
const LIMIT = 65536;
const UINT_MAX = (1n << 256n) - 1n;
const FAILURE_DETAILS = new WeakMap();
const DETAIL_FIELDS = Object.freeze(['data', 'result', 'response', 'errors', 'error', 'message', 'status', 'chainId',
  'principal', 'agent', 'executorAddress', 'owner', 'agentMandateAddress', 'selector', 'action', 'spec', 'supported',
  'hasAmount', 'amountIndex', 'complianceProviderAddress', 'identityRef', 'eligible', 'reasonCode', 'expiresAt',
  'frozen', 'nonce']);
const MISSING = Symbol('missing');
export class BrickkenReadError extends Error {
  constructor(code, status = 0) { super(code); this.name = 'BrickkenReadError'; this.code = code; this.status = status; }
}
const fail = (code, status) => { throw new BrickkenReadError(code, status); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export function getBrickkenReadFailureDetails(error) {
  const details = FAILURE_DETAILS.get(error);
  return details === undefined ? undefined : structuredClone(details);
}
function valueType(value) {
  if (value === MISSING || value === undefined) return 'missing';
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'object') return 'object';
  if (typeof value === 'string') return 'string';
  if (typeof value === 'number') return 'number';
  return typeof value === 'boolean' ? 'boolean' : 'missing';
}
function child(value, key) { return object(value) && Object.hasOwn(value, key) ? value[key] : MISSING; }
function shapeObservation(path, value) {
  const result = { path, type: valueType(value) };
  if (object(value)) {
    result.fields = {};
    for (const field of DETAIL_FIELDS) result.fields[field] = valueType(Object.hasOwn(value, field) ? value[field] : MISSING);
  }
  return result;
}
function projectShape(json) {
  const data = child(json, 'data');
  const values = [
    ['root', json], ['data', data], ['result', child(json, 'result')], ['response', child(json, 'response')],
    ['data.data', child(data, 'data')], ['data.result', child(data, 'result')], ['data.response', child(data, 'response')],
    ['data.spec', child(data, 'spec')], ['data.mandate', child(data, 'mandate')],
    ['root.spec', child(json, 'spec')], ['root.mandate', child(json, 'mandate')],
    ['data[0]', Array.isArray(data) && data.length ? data[0] : MISSING]
  ];
  return values.map(([path, value]) => shapeObservation(path, value));
}
function mediaTypeClass(value) {
  if (typeof value !== 'string' || !value.trim()) return 'missing';
  const type = value.split(';', 1)[0].trim().toLowerCase();
  if (type === 'application/json' || type.endsWith('+json')) return 'json';
  if (type === 'text/html' || type === 'application/xhtml+xml') return 'html';
  if (type.startsWith('text/')) return 'text';
  return 'other';
}
function address(value) {
  if (typeof value !== 'string' || !/^0x[\da-f]{40}$/i.test(value) || /^0x0{40}$/i.test(value)) fail('ADDRESS_INVALID');
  return value.toLowerCase();
}
function uint(value) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(value) || BigInt(value) > UINT_MAX) fail('UINT_INVALID');
  return value;
}
function bool(value) { if (typeof value !== 'boolean') fail('RESPONSE_INVALID'); return value; }
function equalsAddress(actual, expected) { if (address(actual) !== expected) fail('RESPONSE_IDENTITY_MISMATCH'); }
function exactInput(input, fields) {
  if (!object(input) || Object.keys(input).length !== fields.length || fields.some(field => !Object.hasOwn(input, field))) fail('READ_INPUT_INVALID');
}

// Fixed routes and canonical query fields prevent arbitrary credential destinations.
export function buildBrickkenRead(input) {
  if (!object(input)) fail('READ_INPUT_INVALID');
  const common = ['kind', 'chainId', 'principal', 'agent'];
  const fields = input.kind === 'executor' ? ['kind', 'chainId', 'principal', 'executorAddress']
    : input.kind === 'compliance' ? ['kind', 'chainId', 'principal', 'identityRef'] : input.kind === 'mandate' ? common
      : input.kind === 'can-execute' ? [...common, 'asset', 'amount'] : null;
  if (!fields) fail('READ_KIND_INVALID');
  exactInput(input, fields);
  if (input.chainId !== CHAIN) fail('CHAIN_DENIED');
  const expected = { kind: input.kind, principal: address(input.principal) };
  const query = new URLSearchParams({ chainId: CHAIN });
  let route;
  if (input.kind === 'compliance') {
    if (typeof input.identityRef !== 'string' || !/^0x[\da-f]{64}$/i.test(input.identityRef)) fail('IDENTITY_REF_INVALID');
    expected.identityRef = input.identityRef.toLowerCase();
    query.set('principal', expected.principal); query.set('identityRef', expected.identityRef);
    query.set('complianceProviderAddress', PROVIDER); route = '/rams/compliance-status';
  } else if (input.kind === 'executor') {
    expected.executorAddress = address(input.executorAddress);
    if (expected.executorAddress === PLATFORM_EXECUTOR || expected.executorAddress === expected.principal) fail('EXECUTOR_DENIED');
    query.set('executorAddress', expected.executorAddress); query.set('selector', SELECTOR);
    route = '/rams/executor-action';
  } else {
    expected.agent = address(input.agent);
    if (expected.agent === expected.principal) fail('ACTOR_COLLISION');
    query.set('principal', expected.principal); query.set('agent', expected.agent);
    query.set('agentMandateAddress', REGISTRY);
    route = '/rams/mandate';
    if (input.kind === 'can-execute') {
      expected.asset = address(input.asset); expected.amount = uint(input.amount);
      query.set('asset', expected.asset); query.set('amount', expected.amount); query.set('selector', SELECTOR);
      route = '/rams/can-execute';
    }
  }
  return Object.freeze({ url: ORIGIN + route + '?' + query, expected: Object.freeze(expected) });
}

// Project a typed allowlist, never arbitrary response/error text. This is API evidence,
// not an independent RPC check or authorization to execute a transaction.
function projectResponse(json, expected) {
  // Live sandbox reports on 14 September have a direct payload; docs wrap it in data.
  // Select exactly one shape. Never fall back from a malformed or mixed envelope.
  if (!object(json) || ['errors', 'error', 'result', 'response'].some(key => Object.hasOwn(json, key))) fail('RESPONSE_INVALID');
  const wrapped = Object.hasOwn(json, 'data');
  if (wrapped && ['chainId', 'principal', 'agent', 'executorAddress', 'owner', 'agentMandateAddress',
    'selector', 'action', 'spec', 'complianceProviderAddress', 'identityRef', 'eligible', 'frozen', 'nonce']
    .some(key => Object.hasOwn(json, key))) fail('RESPONSE_INVALID');
  const data = wrapped ? json.data : json;
  if (!object(data)) fail('RESPONSE_INVALID');
  if (['errors', 'error', 'result', 'response', 'data'].some(key => Object.hasOwn(data, key))) fail('RESPONSE_INVALID');
  // Some documented responses omit chain/registry echoes. Do not invent observed evidence.
  if (Object.hasOwn(data, 'chainId') && data.chainId !== CHAIN) fail('RESPONSE_IDENTITY_MISMATCH');
  if (Object.hasOwn(data, 'agentMandateAddress')) equalsAddress(data.agentMandateAddress, REGISTRY);
  equalsAddress(data.principal, expected.principal);
  if (expected.kind === 'compliance') {
    equalsAddress(data.complianceProviderAddress, PROVIDER);
    if (typeof data.identityRef !== 'string' || data.identityRef.toLowerCase() !== expected.identityRef) fail('RESPONSE_IDENTITY_MISMATCH');
    if (!Number.isSafeInteger(data.reasonCode) || data.reasonCode < 0 || !Number.isSafeInteger(data.expiresAt) || data.expiresAt < 0) fail('RESPONSE_INVALID');
    return { kind: expected.kind, requestedChainId: CHAIN, responseChainIdObserved: Object.hasOwn(data, 'chainId'),
      principal: expected.principal, identityRef: expected.identityRef, complianceProvider: PROVIDER,
      eligible: bool(data.eligible), reasonCode: data.reasonCode, expiresAt: data.expiresAt,
      evidenceKind: 'brickken-api-read', independentRpcVerified: false };
  }
  if (expected.kind === 'executor') {
    equalsAddress(data.executorAddress, expected.executorAddress);
    equalsAddress(data.owner, expected.principal);
    equalsAddress(data.agentMandateAddress, REGISTRY);
    if (data.selector !== SELECTOR || data.action !== ACTION || !object(data.spec)) fail('RESPONSE_INVALID');
    if (!Number.isInteger(data.spec.amountIndex) || data.spec.amountIndex < 0 || data.spec.amountIndex > 255) fail('RESPONSE_INVALID');
    const spec = { supported: bool(data.spec.supported), hasAmount: bool(data.spec.hasAmount), amountIndex: data.spec.amountIndex };
    return { kind: expected.kind, requestedChainId: CHAIN, responseChainIdObserved: Object.hasOwn(data, 'chainId'), executorAddress: expected.executorAddress,
      principal: expected.principal, registry: REGISTRY, spec,
      valueExtractionReady: spec.supported && spec.hasAmount && spec.amountIndex === 2,
      recorderRoleVerified: false, independentRpcVerified: false };
  }
  equalsAddress(data.agent, expected.agent);
  if (expected.kind === 'can-execute') {
    equalsAddress(data.asset, expected.asset);
    if (data.amount !== expected.amount || data.selector !== SELECTOR || data.action !== ACTION || !object(data.checks)) fail('RESPONSE_INVALID');
    const checks = {};
    for (const key of ['mandateExists', 'assetMatches', 'withinValidityWindow', 'notRevoked', 'actionEnabled', 'agentNotFrozen', 'withinTransactionCap', 'withinCumulativeCap']) checks[key] = bool(data.checks[key]);
    return { kind: expected.kind, requestedChainId: CHAIN, responseChainIdObserved: Object.hasOwn(data, 'chainId'),
      requestedRegistry: REGISTRY, responseRegistryObserved: Object.hasOwn(data, 'agentMandateAddress'), principal: expected.principal, agent: expected.agent,
      asset: expected.asset, amount: expected.amount, allowed: bool(data.allowed), checks,
      evidenceKind: 'brickken-api-read', independentRpcVerified: false, transactionSent: false };
  }
  if (data.chainId !== CHAIN || !['none', 'pending', 'active', 'expired', 'revoked'].includes(data.status)) fail('RESPONSE_INVALID');
  equalsAddress(data.agentMandateAddress, REGISTRY);
  // A deliberately small summary; grant/execute must validate the complete mandate later.
  return { kind: expected.kind, chainId: CHAIN, principal: expected.principal, agent: expected.agent,
    status: data.status, frozen: bool(data.frozen), nonce: uint(data.nonce),
    evidenceKind: 'brickken-api-read', completeMandateVerified: false, independentRpcVerified: false };
}

export function classifyBrickkenFailure(status, body) {
  // Only fixed categories escape this function. Never expose server echoes of credentials.
  if (status === 402) return 'PAYMENT_REQUIRED_NO_PAYMENT_ATTEMPTED';
  if (status === 429) return 'RATE_LIMITED';
  if (/unauthorized token symbol|token.{0,30}(not found|not registered|does not exist)/i.test(body)) return 'TOKEN_SCOPE_OR_REGISTRATION';
  if (/out of credits|quota exceeded/i.test(body)) return 'CREDITS_OR_QUOTA';
  if (/signer.{0,50}whitelist|wallet.{0,50}whitelist/i.test(body)) return 'SIGNER_WHITELIST';
  if (status === 401) return 'AUTHENTICATION_REJECTED';
  if (status === 403) return 'ACCESS_DENIED';
  return 'HTTP_ERROR';
}

async function boundedBody(response, observeSize = () => {}) {
  if (!response.body?.getReader) fail('RESPONSE_INVALID');
  const reader = response.body.getReader(); const chunks = []; let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength;
      observeSize(size);
      if (size > LIMIT) { try { await reader.cancel(); } catch {} fail('RESPONSE_TOO_LARGE'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
}

// Caller must separately obtain authorization for an exact credential-use path.
// No environment/clipboard/credential-store discovery, retry, payment or persistence.
export async function readBrickken(input, { apiKey, fetchImpl = globalThis.fetch } = {}) {
  const request = buildBrickkenRead(input);
  if (typeof apiKey !== 'string' || !apiKey.length || apiKey.length > 4096 || /[^\x21-\x7e]/.test(apiKey)) fail('KEY_INPUT_INVALID');
  const details = { stage: 'fetch', httpStatus: 0, mediaTypeClass: 'missing', bodyBytes: 0, jsonRootType: 'missing' };
  try {
    const response = await fetchImpl(request.url, {
      method: 'GET', headers: { 'x-api-key': apiKey, Accept: 'application/json' },
      redirect: 'error', credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(15000)
    });
    details.stage = 'header';
    details.httpStatus = Number.isSafeInteger(response?.status) ? response.status : 0;
    details.mediaTypeClass = mediaTypeClass(response?.headers?.get?.('content-type'));
    if (response.redirected || (response.url && response.url !== request.url)) fail('REDIRECT_DENIED');
    if (response.status >= 300 && response.status < 400) fail('REDIRECT_DENIED');
    details.stage = 'body';
    const body = await boundedBody(response, size => { details.bodyBytes = size; });
    if (response.status !== 200) fail(classifyBrickkenFailure(response.status, body), response.status);
    if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')) {
      details.stage = 'header'; fail('RESPONSE_INVALID');
    }
    details.stage = 'json';
    let json; try { json = JSON.parse(body); } catch { fail('RESPONSE_INVALID'); }
    details.jsonRootType = valueType(json);
    details.stage = 'schema';
    details.shape = projectShape(json);
    return projectResponse(json, request.expected);
  } catch (error) {
    const outgoing = error instanceof BrickkenReadError ? error : new BrickkenReadError('READ_FAILED');
    FAILURE_DETAILS.set(outgoing, structuredClone(details));
    // Native fetch/parsing errors can contain URLs or arbitrary response content.
    throw outgoing;
  } finally { apiKey = null; }
}
