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
