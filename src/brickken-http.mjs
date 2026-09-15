// Bounded Brickken prepare caller. Credentials and fetch are injected only in
// memory. This module never retries, follows redirects, pays, signs or sends.
export const BRICKKEN_SANDBOX_ORIGIN = 'https://api.sandbox.brickken.com';
export const BRICKKEN_PREPARE_URL = BRICKKEN_SANDBOX_ORIGIN + '/prepare-transactions';
export const DEFAULT_HTTP_TIMEOUT_MS = 10_000;
export const DEFAULT_HTTP_RESPONSE_BYTES = 65_536;
export const DEFAULT_HTTP_REQUEST_BYTES = 65_536;

export class BrickkenHttpError extends Error {
  constructor(code, status = null) {
    super(code);
    this.name = 'BrickkenHttpError';
    this.code = code;
    this.status = status;
  }
}

function fail(code, status = null) { throw new BrickkenHttpError(code, status); }

function positiveInteger(value, code, maximum) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) fail(code);
  return value;
}

function credential(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096 || /[\r\n\0]/.test(value)) {
    fail('CREDENTIAL_INVALID');
  }
  return value;
}

function requestBody(value, maximum) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('REQUEST_INVALID');
  let encoded;
  try { encoded = JSON.stringify(value); } catch { fail('REQUEST_INVALID'); }
  if (typeof encoded !== 'string' || Buffer.byteLength(encoded, 'utf8') > maximum) fail('REQUEST_TOO_LARGE');
  return encoded;
}

function classifyStatus(status) {
  if (status === 402) fail('PAYMENT_REQUIRED', status);
  if (status === 401 || status === 403) fail('AUTHORIZATION_DENIED', status);
  fail('HTTP_REJECTED', status);
}

async function boundedBody(response, maximum) {
  const contentLength = response.headers?.get?.('content-length');
  if (contentLength !== null && contentLength !== undefined) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength) || BigInt(contentLength) > BigInt(maximum)) {
      fail('RESPONSE_TOO_LARGE');
    }
  }
  const reader = response.body?.getReader?.();
  if (!reader) fail('RESPONSE_STREAM_REQUIRED');
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let bytes = 0;
  let text = '';
  try {
    while (true) {
      const part = await reader.read();
      if (!part || typeof part.done !== 'boolean') fail('RESPONSE_INVALID');
      if (part.done) break;
      if (!(part.value instanceof Uint8Array)) fail('RESPONSE_INVALID');
      bytes += part.value.byteLength;
      if (bytes > maximum) fail('RESPONSE_TOO_LARGE');
      text += decoder.decode(part.value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } catch (error) {
    try { await reader.cancel(); } catch { /* best-effort cancellation */ }
    if (error instanceof BrickkenHttpError) throw error;
    fail('RESPONSE_READ_FAILED');
  }
}

export async function postBrickkenPrepare({
  credential: credentialInput,
  body,
  fetchImpl,
  timeoutMs = DEFAULT_HTTP_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_HTTP_RESPONSE_BYTES,
  maxRequestBytes = DEFAULT_HTTP_REQUEST_BYTES
}) {
  if (typeof fetchImpl !== 'function') fail('FETCH_REQUIRED');
  const apiKey = credential(credentialInput);
  const timeout = positiveInteger(timeoutMs, 'TIMEOUT_INVALID', 60_000);
  const responseLimit = positiveInteger(maxResponseBytes, 'RESPONSE_LIMIT_INVALID', 1_048_576);
  const requestLimit = positiveInteger(maxRequestBytes, 'REQUEST_LIMIT_INVALID', 1_048_576);
  const encoded = requestBody(body, requestLimit);
  const controller = new AbortController();
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new BrickkenHttpError('HTTP_TIMEOUT'));
    }, timeout);
  });
  try {
    const operation = (async () => {
      let response;
      try {
        response = await fetchImpl(BRICKKEN_PREPARE_URL, {
          method: 'POST',
          headers: Object.freeze({
            accept: 'application/json',
            'content-type': 'application/json',
            'x-api-key': apiKey
          }),
          body: encoded,
          redirect: 'error',
          credentials: 'omit',
          referrerPolicy: 'no-referrer',
          signal: controller.signal
        });
      } catch (error) {
        if (controller.signal.aborted) fail('HTTP_TIMEOUT');
        fail('NETWORK_FAILED');
      }
      if (!response || !Number.isSafeInteger(response.status) ||
          response.status < 100 || response.status > 599) fail('RESPONSE_INVALID');
      // P9: classify every non-200 before reading, parsing or inspecting its body.
      if (response.status !== 200) classifyStatus(response.status);
      if (response.redirected === true || (response.url && response.url !== BRICKKEN_PREPARE_URL)) {
        fail('REDIRECT_REJECTED');
      }
      return boundedBody(response, responseLimit);
    })();
    return await Promise.race([operation, deadline]);
  } catch (error) {
    if (error instanceof BrickkenHttpError) throw error;
    fail('HTTP_FAILED');
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

// Live client-signed routes. The OpenAPI document read on 2026-09-14 lists no
// RAMS method on /prepare-transactions; RAMS writes are prepared on the
// /x402/rams facades, which accept x-api-key instead of payment. A 402 stops
// the step because no payment path exists. Only these fixed sandbox URLs can
// receive the key, and the responses are returned as bounded text for strict
// parsing by the caller.
export const BRICKKEN_RAMS_PREPARE_PATHS = Object.freeze({
  setAction: '/x402/rams/set-executor-action',
  grant: '/x402/rams/grant-mandate',
  execute: '/x402/rams/execute',
  revoke: '/x402/rams/revoke-mandate'
});
export const BRICKKEN_SEND_URL = BRICKKEN_SANDBOX_ORIGIN + '/send-transactions';
export const BRICKKEN_STATUS_URL = BRICKKEN_SANDBOX_ORIGIN + '/get-transaction-status';
const API_ERROR_CODE = /^[A-Za-z0-9_]{1,64}$/;

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

async function exchange({ url, method, credentialInput, encoded, fetchImpl, timeoutMs, maxResponseBytes }) {
  if (typeof fetchImpl !== 'function') fail('FETCH_REQUIRED');
  const apiKey = credential(credentialInput);
  const timeout = positiveInteger(timeoutMs, 'TIMEOUT_INVALID', 60_000);
  const responseLimit = positiveInteger(maxResponseBytes, 'RESPONSE_LIMIT_INVALID', 1_048_576);
  const controller = new AbortController();
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new BrickkenHttpError('HTTP_TIMEOUT'));
    }, timeout);
  });
  try {
    const operation = (async () => {
      let response;
      try {
        response = await fetchImpl(url, {
          method,
          headers: Object.freeze(encoded === null
            ? { accept: 'application/json', 'x-api-key': apiKey }
            : { accept: 'application/json', 'content-type': 'application/json', 'x-api-key': apiKey }),
          ...(encoded === null ? {} : { body: encoded }),
          redirect: 'error',
          credentials: 'omit',
          referrerPolicy: 'no-referrer',
          signal: controller.signal
        });
      } catch {
        if (controller.signal.aborted) fail('HTTP_TIMEOUT');
        fail('NETWORK_FAILED');
      }
      if (!response || !Number.isSafeInteger(response.status) ||
          response.status < 100 || response.status > 599) fail('RESPONSE_INVALID');
      // Classify every non-200 status first, as postBrickkenPrepare does; the
      // redirect check then applies to the only status whose body is read.
      if (response.status === 402) fail('PAYMENT_REQUIRED', 402);
      if (response.status === 401 || response.status === 403) fail('AUTHORIZATION_DENIED', response.status);
      if (response.status === 429) fail('RATE_LIMITED', 429);
      if (response.status === 400) {
        // Keep only a short machine code from the documented error object, never message text.
        let apiErrorCode = null;
        try {
          const parsed = JSON.parse(await boundedBody(response, 8192));
          const candidate = parsed?.error?.code;
          if (typeof candidate === 'string' && API_ERROR_CODE.test(candidate)) apiErrorCode = candidate;
        } catch { /* The status alone classifies the failure. */ }
        const rejected = new BrickkenHttpError('HTTP_REJECTED', 400);
        rejected.apiErrorCode = apiErrorCode;
        throw rejected;
      }
      if (response.status !== 200) fail('HTTP_REJECTED', response.status);
      if (response.redirected === true || (response.url && response.url !== url)) fail('REDIRECT_REJECTED');
      return boundedBody(response, responseLimit);
    })();
    return await Promise.race([operation, deadline]);
  } catch (error) {
    if (error instanceof BrickkenHttpError) throw error;
    fail('HTTP_FAILED');
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

export async function postBrickkenRamsPrepare({
  credential: credentialInput,
  operation,
  body,
  fetchImpl,
  timeoutMs = DEFAULT_HTTP_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_HTTP_RESPONSE_BYTES,
  maxRequestBytes = DEFAULT_HTTP_REQUEST_BYTES
}) {
  if (typeof operation !== 'string' || !Object.hasOwn(BRICKKEN_RAMS_PREPARE_PATHS, operation)) fail('OPERATION_DENIED');
  const encoded = requestBody(body, positiveInteger(maxRequestBytes, 'REQUEST_LIMIT_INVALID', 1_048_576));
  return exchange({
    url: BRICKKEN_SANDBOX_ORIGIN + BRICKKEN_RAMS_PREPARE_PATHS[operation],
    method: 'POST', credentialInput, encoded, fetchImpl, timeoutMs, maxResponseBytes
  });
}

export async function postBrickkenSend({
  credential: credentialInput,
  txId,
  signedTransaction,
  fetchImpl,
  timeoutMs = DEFAULT_HTTP_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_HTTP_RESPONSE_BYTES
}) {
  if (typeof txId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(txId)) fail('TX_ID_INVALID');
  if (typeof signedTransaction !== 'string' || signedTransaction.length > 2 + 2 * 32_768 ||
      !/^0x(?:[0-9a-f]{2})+$/.test(signedTransaction)) fail('SIGNED_TRANSACTION_INVALID');
  // The documented client-signed shape: one txId string and one signed hex string.
  const encoded = requestBody({ txId, signedTransactions: signedTransaction }, DEFAULT_HTTP_REQUEST_BYTES * 2);
  return exchange({ url: BRICKKEN_SEND_URL, method: 'POST', credentialInput, encoded, fetchImpl, timeoutMs, maxResponseBytes });
}

export async function getBrickkenTransactionStatus({
  credential: credentialInput,
  transactionHash,
  fetchImpl,
  timeoutMs = DEFAULT_HTTP_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_HTTP_RESPONSE_BYTES
}) {
  if (typeof transactionHash !== 'string' || !/^0x[0-9a-f]{64}$/.test(transactionHash)) fail('TRANSACTION_HASH_INVALID');
  return exchange({
    url: BRICKKEN_STATUS_URL + '?hash=' + transactionHash,
    method: 'GET', credentialInput, encoded: null, fetchImpl, timeoutMs, maxResponseBytes
  });
}

function responseRoot(text) {
  if (typeof text !== 'string') fail('RESPONSE_INVALID');
  let json;
  try { json = JSON.parse(text); } catch { fail('RESPONSE_INVALID'); }
  if (!plainObject(json)) fail('RESPONSE_INVALID');
  if (Object.hasOwn(json, 'data')) {
    if (Object.keys(json).length !== 1 || !plainObject(json.data)) fail('RESPONSE_INVALID');
    return json.data;
  }
  return json;
}

// The relay's hash is an observation to compare with the locally computed
// Ethereum hash, never a substitute for it.
export function parseBrickkenSendResponse(text) {
  const root = responseRoot(text);
  if (typeof root.txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(root.txHash)) fail('RESPONSE_INVALID');
  const status = typeof root.status === 'string' && /^[a-z_-]{1,32}$/.test(root.status) ? root.status : null;
  return Object.freeze({ txHash: root.txHash.toLowerCase(), status });
}

export function parseBrickkenStatusResponse(text) {
  const root = responseRoot(text);
  if (!['pending', 'success', 'rejected'].includes(root.status)) fail('RESPONSE_INVALID');
  let transactionHash = null;
  if (root.transactionHash !== undefined && root.transactionHash !== null) {
    if (typeof root.transactionHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(root.transactionHash)) fail('RESPONSE_INVALID');
    transactionHash = root.transactionHash.toLowerCase();
  }
  return Object.freeze({
    status: root.status,
    transactionHash,
    errorReported: typeof root.error === 'string' && root.error.length > 0
  });
}
