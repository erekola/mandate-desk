// Bounded Ethereum Sepolia JSON-RPC reader and raw-transaction relay for two
// fixed public endpoints. This module holds no keys, performs no signing, and
// never retries or follows redirects.

export const SEPOLIA_CHAIN_ID = '11155111';
export const SEPOLIA_RPC_ENDPOINTS = Object.freeze({
  primary: 'https://ethereum-sepolia-rpc.publicnode.com',
  secondary: 'https://sepolia.rpc.thirdweb.com'
});

const MESSAGE_MAX_CHARS = 160;
const SIGNED_TX_MAX_BYTES = 512 * 1024;

export class SepoliaRpcError extends Error {
  constructor(code, method = null) {
    super(code);
    this.name = 'SepoliaRpcError';
    this.code = code;
    this.method = method;
  }
}

function fail(code, method = null) { throw new SepoliaRpcError(code, method); }

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

// Response-side strict parsers: a violation always means the provider sent an
// invalid JSON-RPC payload, never a caller mistake.
function respQuantity(value, method) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{1,64}$/.test(value)) fail('RESPONSE_INVALID', method);
  return BigInt(value).toString(10);
}
function respQuantityNumber(value, method) {
  const decimal = respQuantity(value, method);
  const number = Number(decimal);
  if (!Number.isSafeInteger(number)) fail('RESPONSE_INVALID', method);
  return number;
}
function respData(value, method) {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(value)) fail('RESPONSE_INVALID', method);
  return value.toLowerCase();
}
function respAddress(value, method) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) fail('RESPONSE_INVALID', method);
  return value.toLowerCase();
}
function respHash(value, method) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) fail('RESPONSE_INVALID', method);
  return value.toLowerCase();
}

// Caller-side strict parsers: a violation is always the caller's mistake,
// made before any request is sent.
function inputAddress(value, method) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) fail('INPUT_INVALID', method);
  return value.toLowerCase();
}
function inputData(value, method) {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(value)) fail('INPUT_INVALID', method);
  return value.toLowerCase();
}
function inputHash(value, method) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) fail('INPUT_INVALID', method);
  return value.toLowerCase();
}
function inputDecimalUint(value, method) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) fail('INPUT_INVALID', method);
  return value;
}

function sanitizeMessage(value) {
  let out = '';
  for (const char of value) {
    const point = char.codePointAt(0);
    if (point >= 0x20 && point <= 0x7e) out += char;
    if (out.length >= MESSAGE_MAX_CHARS) break;
  }
  return out.slice(0, MESSAGE_MAX_CHARS);
}

// Builds the internal, classification-only error shape. Never returned for
// display: messages are sanitized and only used for pattern matching.
function classifiedError(raw, method) {
  if (!plainObject(raw)) fail('RESPONSE_INVALID', method);
  const code = Number.isInteger(raw.code) ? raw.code : null;
  const message = sanitizeMessage(typeof raw.message === 'string' ? raw.message : '');
  const data = typeof raw.data === 'string' && /^0x(?:[0-9a-fA-F]{2})*$/.test(raw.data) ? raw.data.toLowerCase() : null;
  return { error: { code, message, data } };
}

function isClassifiedError(value) {
  return value !== null && typeof value === 'object' && Object.hasOwn(value, 'error');
}

function isRevert(errorInfo) {
  const message = errorInfo.message.toLowerCase();
  return errorInfo.code === 3 || message.includes('execution reverted') || message.includes('revert');
}

async function boundedRpcBody(response, maximum, method) {
  const contentLength = response.headers?.get?.('content-length');
  if (contentLength !== null && contentLength !== undefined) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength) || BigInt(contentLength) > BigInt(maximum)) {
      fail('RESPONSE_TOO_LARGE', method);
    }
  }
  const reader = response.body?.getReader?.();
  if (!reader) fail('RESPONSE_INVALID', method);
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let bytes = 0;
  let text = '';
  try {
    while (true) {
      const part = await reader.read();
      if (!part || typeof part.done !== 'boolean') fail('RESPONSE_INVALID', method);
      if (part.done) break;
      if (!(part.value instanceof Uint8Array)) fail('RESPONSE_INVALID', method);
      bytes += part.value.byteLength;
      if (bytes > maximum) fail('RESPONSE_TOO_LARGE', method);
      text += decoder.decode(part.value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } catch (error) {
    try { await reader.cancel(); } catch { /* best-effort cancellation */ }
    if (error instanceof SepoliaRpcError) throw error;
    fail('RESPONSE_INVALID', method);
  }
}

function buildCallInput(input, method) {
  if (!plainObject(input)) fail('INPUT_INVALID', method);
  const keys = Object.keys(input);
  if (!keys.includes('to') || !keys.includes('data')) fail('INPUT_INVALID', method);
  if (keys.some(key => !['from', 'to', 'data'].includes(key))) fail('INPUT_INVALID', method);
  const callObject = { to: inputAddress(input.to, method), data: inputData(input.data, method) };
  if (Object.hasOwn(input, 'from')) callObject.from = inputAddress(input.from, method);
  return callObject;
}

function normalizeRpcLog(log, method) {
  if (!plainObject(log)) fail('RESPONSE_INVALID', method);
  const required = ['address', 'topics', 'data', 'transactionHash', 'blockNumber', 'blockHash', 'logIndex'];
  for (const key of required) if (!Object.hasOwn(log, key)) fail('RESPONSE_INVALID', method);
  if (!Array.isArray(log.topics) || log.topics.length > 4) fail('RESPONSE_INVALID', method);
  const removed = Object.hasOwn(log, 'removed') ? log.removed : false;
  if (typeof removed !== 'boolean') fail('RESPONSE_INVALID', method);
  return {
    address: respAddress(log.address, method),
    topics: log.topics.map(topic => respHash(topic, method)),
    data: respData(log.data, method),
    transactionHash: respHash(log.transactionHash, method),
    blockNumber: respQuantity(log.blockNumber, method),
    blockHash: respHash(log.blockHash, method),
    logIndex: respQuantity(log.logIndex, method),
    removed
  };
}

/**
 * Formats a caller block reference into the value a JSON-RPC call expects.
 * Accepts the tag strings 'latest' | 'pending' | 'safe' | 'finalized', a
 * `{ blockNumber: '<decimal string>' }` object (minimal 0x hex), or a
 * `{ blockHash: '0x<64 hex>' }` object (EIP-1898, requireCanonical: true).
 * Anything else fails BLOCK_REF_INVALID before any request is sent, always
 * with method: null since this function has no request context of its own.
 */
export function blockRef(value) {
  if (value === 'latest' || value === 'pending' || value === 'safe' || value === 'finalized') return value;
  if (plainObject(value)) {
    const keys = Object.keys(value);
    if (keys.length === 1 && keys[0] === 'blockNumber') {
      if (typeof value.blockNumber !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value.blockNumber)) fail('BLOCK_REF_INVALID');
      return '0x' + BigInt(value.blockNumber).toString(16);
    }
    if (keys.length === 1 && keys[0] === 'blockHash') {
      if (typeof value.blockHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value.blockHash)) fail('BLOCK_REF_INVALID');
      return Object.freeze({ blockHash: value.blockHash.toLowerCase(), requireCanonical: true });
    }
  }
  fail('BLOCK_REF_INVALID');
}

export class SepoliaRpc {
  #fetchImpl;
  #timeoutMs;
  #maxResponseBytes;
  #url;
  #href;
  #nextId = 1;

  constructor({ endpoint, fetchImpl = globalThis.fetch, timeoutMs = 15000, maxResponseBytes = 2_000_000 } = {}) {
    const entry = Object.entries(SEPOLIA_RPC_ENDPOINTS).find(([, url]) => url === endpoint);
    if (!entry) fail('ENDPOINT_DENIED');
    this.endpointName = entry[0];
    this.#url = entry[1];
    // fetch reports the normalized URL, which adds '/' to an empty path.
    this.#href = new URL(entry[1]).href;
    if (typeof fetchImpl !== 'function') fail('INPUT_INVALID');
    this.#fetchImpl = fetchImpl;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) fail('INPUT_INVALID');
    this.#timeoutMs = timeoutMs;
    if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > 8_000_000) fail('INPUT_INVALID');
    this.#maxResponseBytes = maxResponseBytes;
  }

  async #request(method, params, { classifyErrors = false } = {}) {
    const id = this.#nextId;
    this.#nextId += 1;
    const payload = JSON.stringify({ jsonrpc: '2.0', method, params, id });
    const controller = new AbortController();
    let timer;
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new SepoliaRpcError('RPC_TIMEOUT', method));
      }, this.#timeoutMs);
    });
    try {
      const operation = (async () => {
        let response;
        try {
          response = await this.#fetchImpl(this.#url, {
            method: 'POST',
            headers: Object.freeze({ accept: 'application/json', 'content-type': 'application/json' }),
            body: payload,
            redirect: 'error',
            credentials: 'omit',
            referrerPolicy: 'no-referrer',
            signal: controller.signal
          });
        } catch {
          if (controller.signal.aborted) fail('RPC_TIMEOUT', method);
          fail('NETWORK_FAILED', method);
        }
        if (!response) fail('NETWORK_FAILED', method);
        if (response.status !== 200) fail(response.status === 429 ? 'HTTP_429' : 'HTTP_REJECTED', method);
        if (response.redirected === true || (response.url && response.url !== this.#url && response.url !== this.#href)) {
          fail('REDIRECT_REJECTED', method);
        }
        const text = await boundedRpcBody(response, this.#maxResponseBytes, method);
        let parsed;
        try { parsed = JSON.parse(text); } catch { fail('RESPONSE_INVALID', method); }
        const hasResult = plainObject(parsed) && Object.hasOwn(parsed, 'result');
        const hasError = plainObject(parsed) && Object.hasOwn(parsed, 'error');
        if (!plainObject(parsed) || parsed.jsonrpc !== '2.0' || parsed.id !== id || hasResult === hasError) {
          fail('RESPONSE_INVALID', method);
        }
        if (hasError) {
          const classified = classifiedError(parsed.error, method);
          if (classifyErrors) return classified;
          fail('RPC_ERROR', method);
        }
        return parsed.result;
      })();
      return await Promise.race([operation, deadline]);
    } catch (error) {
      if (error instanceof SepoliaRpcError) throw error;
      fail('NETWORK_FAILED', method);
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  }

  async chainId() {
    const method = 'eth_chainId';
    const result = await this.#request(method, []);
    return respQuantity(result, method);
  }

  async blockNumber() {
    const method = 'eth_blockNumber';
    const result = await this.#request(method, []);
    return respQuantity(result, method);
  }

  async getBlock(ref) {
    if (ref === 'pending') fail('INPUT_INVALID', 'eth_getBlockByNumber');
    const formatted = blockRef(ref);
    const byHash = typeof formatted === 'object';
    const method = byHash ? 'eth_getBlockByHash' : 'eth_getBlockByNumber';
    const result = await this.#request(method, byHash ? [formatted.blockHash, false] : [formatted, false]);
    if (result === null) return null;
    if (!plainObject(result)) fail('RESPONSE_INVALID', method);
    const required = ['number', 'hash', 'parentHash', 'timestamp', 'baseFeePerGas'];
    for (const key of required) if (!Object.hasOwn(result, key)) fail('RESPONSE_INVALID', method);
    return deepFreeze({
      number: respQuantity(result.number, method),
      hash: respHash(result.hash, method),
      parentHash: respHash(result.parentHash, method),
      timestamp: respQuantity(result.timestamp, method),
      baseFeePerGas: respQuantity(result.baseFeePerGas, method)
    });
  }

  async getTransactionCount(address, ref) {
    const method = 'eth_getTransactionCount';
    const addr = inputAddress(address, method);
    const formatted = blockRef(ref);
    const result = await this.#request(method, [addr, formatted]);
    return respQuantity(result, method);
  }

  async getBalance(address, ref) {
    const method = 'eth_getBalance';
    const addr = inputAddress(address, method);
    const formatted = blockRef(ref);
    const result = await this.#request(method, [addr, formatted]);
    return respQuantity(result, method);
  }

  async getCode(address, ref) {
    const method = 'eth_getCode';
    const addr = inputAddress(address, method);
    const formatted = blockRef(ref);
    const result = await this.#request(method, [addr, formatted]);
    return respData(result, method);
  }

  async call(input, ref) {
    const method = 'eth_call';
    const callObject = buildCallInput(input, method);
    const formatted = blockRef(ref);
    const result = await this.#request(method, [callObject, formatted], { classifyErrors: true });
    if (isClassifiedError(result)) {
      if (isRevert(result.error)) return deepFreeze({ ok: false, revertData: result.error.data });
      fail('RPC_ERROR', method);
    }
    return deepFreeze({ ok: true, returnData: respData(result, method) });
  }

  async estimateGas(input, ref = 'latest') {
    const method = 'eth_estimateGas';
    const callObject = buildCallInput(input, method);
    const formatted = blockRef(ref);
    const result = await this.#request(method, [callObject, formatted], { classifyErrors: true });
    if (isClassifiedError(result)) {
      if (isRevert(result.error)) fail('ESTIMATE_REVERTED', method);
      fail('RPC_ERROR', method);
    }
    return respQuantity(result, method);
  }

  async maxPriorityFeePerGas() {
    const method = 'eth_maxPriorityFeePerGas';
    const result = await this.#request(method, []);
    return respQuantity(result, method);
  }

  async getTransactionByHash(hash) {
    const method = 'eth_getTransactionByHash';
    const h = inputHash(hash, method);
    const result = await this.#request(method, [h]);
    if (result === null) return null;
    if (!plainObject(result)) fail('RESPONSE_INVALID', method);
    const required = [
      'hash', 'from', 'to', 'nonce', 'value', 'input', 'type', 'chainId',
      'gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'blockNumber', 'blockHash'
    ];
    for (const key of required) if (!Object.hasOwn(result, key)) fail('RESPONSE_INVALID', method);
    const type = respQuantityNumber(result.type, method);
    if (type !== 2) fail('RESPONSE_INVALID', method);
    const blockNumber = result.blockNumber === null ? null : respQuantity(result.blockNumber, method);
    const blockHash = result.blockHash === null ? null : respHash(result.blockHash, method);
    return deepFreeze({
      hash: respHash(result.hash, method),
      from: respAddress(result.from, method),
      to: respAddress(result.to, method),
      nonce: respQuantity(result.nonce, method),
      value: respQuantity(result.value, method),
      data: respData(result.input, method),
      type,
      chainId: respQuantity(result.chainId, method),
      gasLimit: respQuantity(result.gas, method),
      maxFeePerGas: respQuantity(result.maxFeePerGas, method),
      maxPriorityFeePerGas: respQuantity(result.maxPriorityFeePerGas, method),
      blockNumber,
      blockHash
    });
  }

  async getTransactionReceipt(hash) {
    const method = 'eth_getTransactionReceipt';
    const h = inputHash(hash, method);
    const result = await this.#request(method, [h]);
    if (result === null) return null;
    if (!plainObject(result)) fail('RESPONSE_INVALID', method);
    const required = ['transactionHash', 'status', 'from', 'to', 'blockNumber', 'blockHash', 'gasUsed', 'effectiveGasPrice', 'logs'];
    for (const key of required) if (!Object.hasOwn(result, key)) fail('RESPONSE_INVALID', method);
    const status = respQuantityNumber(result.status, method);
    if (status !== 0 && status !== 1) fail('RESPONSE_INVALID', method);
    if (!Array.isArray(result.logs)) fail('RESPONSE_INVALID', method);
    return deepFreeze({
      transactionHash: respHash(result.transactionHash, method),
      status,
      from: respAddress(result.from, method),
      to: respAddress(result.to, method),
      blockNumber: respQuantity(result.blockNumber, method),
      blockHash: respHash(result.blockHash, method),
      gasUsed: respQuantity(result.gasUsed, method),
      effectiveGasPrice: respQuantity(result.effectiveGasPrice, method),
      logs: result.logs.map(log => normalizeRpcLog(log, method))
    });
  }

  async sendRawTransaction(signedHex) {
    const method = 'eth_sendRawTransaction';
    if (typeof signedHex !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(signedHex) ||
        (signedHex.length - 2) / 2 > SIGNED_TX_MAX_BYTES) fail('INPUT_INVALID', method);
    const hex = signedHex.toLowerCase();
    const result = await this.#request(method, [hex], { classifyErrors: true });
    if (isClassifiedError(result)) {
      const message = result.error.message.toLowerCase();
      if (message.includes('already known') || message.includes('known transaction')) fail('ALREADY_KNOWN', method);
      if (message.includes('nonce too low')) fail('NONCE_TOO_LOW', method);
      if (message.includes('replacement transaction underpriced')) fail('REPLACEMENT_UNDERPRICED', method);
      if (message.includes('insufficient funds')) fail('INSUFFICIENT_FUNDS', method);
      if (message.includes('fee cap less than block base fee') ||
          message.includes('max fee per gas less than block base fee') ||
          message.includes('transaction underpriced')) fail('FEE_TOO_LOW', method);
      fail('RPC_REJECTED', method);
    }
    return respHash(result, method);
  }
}

/**
 * Projects a getTransactionReceipt() result down to exactly the fields
 * src/brickken-postcheck.mjs's normalizeReceipt (RECEIPT_KEYS / LOG_KEYS)
 * accepts when status is 1: {transactionHash,status,from,to,blockNumber,
 * blockHash,logs}, each log exactly {address,topics,data,transactionHash,
 * blockNumber,blockHash,logIndex,removed}.
 */
export function toPostcheckReceipt(receipt) {
  const receiptKeys = ['transactionHash', 'status', 'from', 'to', 'blockNumber', 'blockHash', 'gasUsed', 'effectiveGasPrice', 'logs'];
  if (!plainObject(receipt) || receiptKeys.some(key => !Object.hasOwn(receipt, key))) fail('INPUT_INVALID');
  if (!Array.isArray(receipt.logs)) fail('INPUT_INVALID');
  const logKeys = ['address', 'topics', 'data', 'transactionHash', 'blockNumber', 'blockHash', 'logIndex', 'removed'];
  const logs = receipt.logs.map(log => {
    if (!plainObject(log) || logKeys.some(key => !Object.hasOwn(log, key))) fail('INPUT_INVALID');
    return {
      address: log.address,
      topics: [...log.topics],
      data: log.data,
      transactionHash: log.transactionHash,
      blockNumber: log.blockNumber,
      blockHash: log.blockHash,
      logIndex: log.logIndex,
      removed: log.removed
    };
  });
  return deepFreeze({
    transactionHash: receipt.transactionHash,
    status: receipt.status,
    from: receipt.from,
    to: receipt.to,
    blockNumber: receipt.blockNumber,
    blockHash: receipt.blockHash,
    logs
  });
}

function requireDistinctRpcPair(rpcs) {
  if (!Array.isArray(rpcs) || rpcs.length !== 2 ||
      !(rpcs[0] instanceof SepoliaRpc) || !(rpcs[1] instanceof SepoliaRpc) ||
      rpcs[0].endpointName === rpcs[1].endpointName) fail('INPUT_INVALID');
}

export async function compareBlockAcrossRpcs(rpcs, blockNumber) {
  requireDistinctRpcPair(rpcs);
  const bn = inputDecimalUint(blockNumber, null);
  const blocks = await Promise.all(rpcs.map(rpc => rpc.getBlock({ blockNumber: bn })));
  const hashes = blocks.map(block => block === null ? null : block.hash);
  const agreed = hashes[0] !== null && hashes[1] !== null && hashes[0] === hashes[1];
  return deepFreeze({ agreed, blockNumber: bn, hashes });
}

export async function finalityAcrossRpcs(rpcs, blockNumber, blockHash) {
  requireDistinctRpcPair(rpcs);
  const bn = inputDecimalUint(blockNumber, null);
  const hash = inputHash(blockHash, null);
  const observations = await Promise.all(rpcs.map(async rpc => {
    const finalizedBlock = await rpc.getBlock('finalized');
    const atNumber = await rpc.getBlock({ blockNumber: bn });
    return {
      endpointName: rpc.endpointName,
      finalizedNumber: finalizedBlock === null ? '0' : finalizedBlock.number,
      finalizedHash: finalizedBlock === null ? null : finalizedBlock.hash,
      blockHashAtNumber: atNumber === null ? null : atNumber.hash
    };
  }));
  const finalized = observations.every(observation =>
    BigInt(observation.finalizedNumber) >= BigInt(bn) && observation.blockHashAtNumber === hash);
  return deepFreeze({ finalized, observations });
}
