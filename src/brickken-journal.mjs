// Durable offline transaction identity journal. This module performs no HTTP,
// signing or broadcast. A caller must decode injected fixture bytes with an
// independently pinned Ethereum library before recordSigned can advance state.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { isVerifiedBrickkenPostcheck } from './brickken-postcheck.mjs';
import { LiveLockError, acquireLiveLock } from './live-lock.mjs';

/**
 * @typedef {object} JournalTransaction
 * @property {string} chainId Decimal uint string.
 * @property {string} from Normalized EVM address.
 * @property {string} to Normalized EVM address.
 * @property {string} value Decimal uint string.
 * @property {string} data Even-length 0x-prefixed calldata.
 * @property {string} nonce Decimal uint string.
 * @property {2} type Only EIP-1559 type 2 is accepted.
 * @property {string} gasLimit Decimal uint string.
 * @property {string} maxPriorityFeePerGas Decimal uint string.
 * @property {string} maxFeePerGas Decimal uint string.
 */
/**
 * @typedef {object} PendingBinding
 * @property {string} operationId Stable caller operation identity.
 * @property {'setAction'|'approve'|'grant'|'execute'|'revoke'} operationKind Semantic operation identity.
 * @property {string} txId Brickken preparation batch identity; it is not a chain transaction hash.
 * @property {string} preparationHash Lowercase SHA-256 canonical preparation identity without 0x.
 * @property {JournalTransaction} transaction Complete unsigned transaction expectation.
 * @property {string} createdAt ISO timestamp.
 */
/**
 * recordSigned verifier contract: `(signedTransactionHex) =>
 * { transactionHash: '0x…', transaction: JournalTransaction }`. The callback
 * must decode and Keccak-hash the exact supplied bytes with an independently
 * pinned Ethereum implementation. This journal checks the complete decoded
 * transaction against PendingBinding; it does not implement Ethereum decoding.
 * Only `source: 'injected-fixture'` is accepted by this offline version.
 *
 * Stored record fields are exactly: operationId, operationKind, txId,
 * preparationHash, transaction, createdAt, state, updatedAt, signed,
 * broadcast, confirmation, semanticVerification. Consumers must use get/list
 * rather than editing JSON.
 */

export const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const JOURNAL_STATES = Object.freeze([
  'pending', 'signed', 'broadcast', 'uncertain', 'confirmed', 'semantically_verified'
]);

const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_SIGNED_BYTES = 512 * 1024;
const TX_KEYS = [
  'chainId', 'from', 'to', 'value', 'data', 'nonce', 'type', 'gasLimit',
  'maxPriorityFeePerGas', 'maxFeePerGas'
];
const RECORD_KEYS = [
  'operationId', 'operationKind', 'txId', 'preparationHash', 'transaction', 'createdAt', 'state',
  'updatedAt', 'signed', 'broadcast', 'confirmation', 'semanticVerification'
];
const WAIT = new Int32Array(new SharedArrayBuffer(4));

export class BrickkenJournalError extends Error {
  constructor(code) {
    super(code);
    this.name = 'BrickkenJournalError';
    this.code = code;
  }
}

function fail(code) { throw new BrickkenJournalError(code); }
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value));
}
function shape(value, keys, code = 'STRUCTURE') {
  if (!plain(value) || Object.keys(value).length !== keys.length ||
      keys.some(key => !Object.hasOwn(value, key))) fail(code);
}
// Exact required keys plus a closed set of optional keys, so a record written
// before an optional field existed still validates.
function shapeWithOptional(value, keys, optional, code = 'STRUCTURE') {
  if (!plain(value) || keys.some(key => !Object.hasOwn(value, key)) ||
      Object.keys(value).some(key => !keys.includes(key) && !optional.includes(key))) fail(code);
}
function identifier(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) fail('IDENTIFIER');
  return value;
}
function iso(value) {
  if (typeof value !== 'string' || new Date(value).toISOString() !== value) fail('TIME');
  return value;
}
function uint(value) {
  if (typeof value !== 'string' || value.length > 78 || !/^(0|[1-9][0-9]*)$/.test(value)) fail('INTEGER');
  return value;
}
function address(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) fail('ADDRESS');
  return value.toLowerCase();
}
function hash32(value, code = 'HASH') {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) fail(code);
  return value.toLowerCase();
}
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (plain(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function exactHex(value, maximumBytes = MAX_SIGNED_BYTES) {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(value) ||
      (value.length - 2) / 2 > maximumBytes) fail('SIGNED_BYTES');
  return value.toLowerCase();
}
function transaction(value) {
  shape(value, TX_KEYS, 'TRANSACTION');
  const result = {
    chainId: uint(value.chainId),
    from: address(value.from),
    to: address(value.to),
    value: uint(value.value),
    data: exactHex(value.data, 256 * 1024),
    nonce: uint(value.nonce),
    type: value.type,
    gasLimit: uint(value.gasLimit),
    maxPriorityFeePerGas: uint(value.maxPriorityFeePerGas),
    maxFeePerGas: uint(value.maxFeePerGas)
  };
  if (result.type !== 2) fail('TRANSACTION_TYPE');
  if (BigInt(result.maxPriorityFeePerGas) > BigInt(result.maxFeePerGas)) fail('TRANSACTION_FEES');
  return result;
}
function same(left, right) { return canonical(left) === canonical(right); }

// The self hash detects accidental or partial local modification. It is stored
// beside the data and is not an authenticity proof or an external anchor.
function documentHash(document) {
  return sha256(Buffer.from(canonical({ schemaVersion: document.schemaVersion, operations: document.operations }), 'utf8'));
}

export function boundedJournalPath(target) {
  const resolved = path.resolve(target);
  if (!resolved.startsWith(PROJECT_ROOT + path.sep)) fail('PATH_SCOPE');
  let current = resolved;
  while (true) {
    const entry = fs.lstatSync(current, { throwIfNoEntry: false });
    if (entry?.isSymbolicLink()) fail('PATH_SCOPE');
    if (current === PROJECT_ROOT) break;
    const parent = path.dirname(current);
    if (parent === current || !parent.startsWith(PROJECT_ROOT)) fail('PATH_SCOPE');
    current = parent;
  }
  return resolved;
}

function validateSigned(value, expected) {
  shape(value, [
    'source', 'signedTransaction', 'ethereumTransactionHash', 'signedBytesSha256',
    'decodedTransaction', 'signedAt'
  ], 'JOURNAL_CORRUPT');
  if (value.source !== 'injected-fixture') fail('JOURNAL_CORRUPT');
  const bytes = exactHex(value.signedTransaction);
  const decoded = transaction(value.decodedTransaction);
  if (!same(decoded, expected) || value.signedBytesSha256 !== sha256(Buffer.from(bytes.slice(2), 'hex')) ||
      hash32(value.ethereumTransactionHash) !== value.ethereumTransactionHash.toLowerCase()) fail('JOURNAL_CORRUPT');
  iso(value.signedAt);
  return value;
}
function validateBroadcast(value, signed) {
  shape(value, ['attempts', 'result', 'lastAttemptAt', 'lastObservationAt'], 'JOURNAL_CORRUPT');
  if (!Number.isSafeInteger(value.attempts) || value.attempts < 1 ||
      !['accepted', 'uncertain', 'recovered-by-hash', 'nonce-conflict'].includes(value.result)) fail('JOURNAL_CORRUPT');
  iso(value.lastAttemptAt);
  if (value.lastObservationAt !== null) iso(value.lastObservationAt);
  if (!signed) fail('JOURNAL_CORRUPT');
  return value;
}
function validateConfirmation(value, signed) {
  shape(value, ['transactionHash', 'blockNumber', 'blockHash', 'confirmations', 'checkedAt'], 'JOURNAL_CORRUPT');
  if (hash32(value.transactionHash) !== signed.ethereumTransactionHash ||
      !Number.isSafeInteger(value.confirmations) || value.confirmations < 1) fail('JOURNAL_CORRUPT');
  uint(value.blockNumber); hash32(value.blockHash); iso(value.checkedAt);
  return value;
}
function validateSemantic(value, confirmation, operationKind) {
  shape(value, ['operationKind', 'transactionHash', 'blockNumber', 'blockHash', 'postcheckSha256', 'verifiedAt'], 'JOURNAL_CORRUPT');
  if (value.operationKind !== operationKind ||
      value.transactionHash !== confirmation.transactionHash || value.blockNumber !== confirmation.blockNumber ||
      value.blockHash !== confirmation.blockHash || !/^[a-f0-9]{64}$/.test(value.postcheckSha256)) fail('JOURNAL_CORRUPT');
  iso(value.verifiedAt);
  return value;
}
function validateRecord(value) {
  shape(value, RECORD_KEYS, 'JOURNAL_CORRUPT');
  identifier(value.operationId); identifier(value.txId);
  if (!['setAction', 'approve', 'grant', 'execute', 'revoke'].includes(value.operationKind)) fail('JOURNAL_CORRUPT');
  if (!/^[a-f0-9]{64}$/.test(value.preparationHash)) fail('JOURNAL_CORRUPT');
  const tx = transaction(value.transaction);
  iso(value.createdAt); iso(value.updatedAt);
  if (!JOURNAL_STATES.includes(value.state)) fail('JOURNAL_CORRUPT');
  const signed = value.signed === null ? null : validateSigned(value.signed, tx);
  const broadcast = value.broadcast === null ? null : validateBroadcast(value.broadcast, signed);
  const confirmation = value.confirmation === null ? null : validateConfirmation(value.confirmation, signed);
  const semantic = value.semanticVerification === null ? null : validateSemantic(value.semanticVerification, confirmation, value.operationKind);
  const requirements = {
    pending: [!signed, !broadcast, !confirmation, !semantic],
    signed: [signed, !broadcast, !confirmation, !semantic],
    broadcast: [signed, broadcast, ['accepted', 'recovered-by-hash'].includes(broadcast?.result), !confirmation, !semantic],
    uncertain: [signed, broadcast, ['uncertain', 'nonce-conflict'].includes(broadcast?.result), !confirmation, !semantic],
    confirmed: [signed, broadcast, confirmation, !semantic],
    semantically_verified: [signed, broadcast, confirmation, semantic]
  }[value.state];
  if (!requirements.every(Boolean)) fail('JOURNAL_CORRUPT');
  return value;
}
function validateDocument(value) {
  shape(value, ['schemaVersion', 'operations', 'selfHash'], 'JOURNAL_CORRUPT');
  if (value.schemaVersion !== 1 || !Array.isArray(value.operations) || value.operations.length > 10000 ||
      !/^[a-f0-9]{64}$/.test(value.selfHash) || documentHash(value) !== value.selfHash) fail('JOURNAL_CORRUPT');
  const operationIds = new Set();
  const txIds = new Set();
  for (const record of value.operations) {
    validateRecord(record);
    if (operationIds.has(record.operationId) || txIds.has(record.txId)) fail('JOURNAL_CORRUPT');
    operationIds.add(record.operationId); txIds.add(record.txId);
  }
  return value;
}
function newDocument() {
  const value = { schemaVersion: 1, operations: [], selfHash: '' };
  value.selfHash = documentHash(value);
  return value;
}
function serializeDocument(value) {
  validateDocument(value);
  const serialized = JSON.stringify(value, null, 2);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_FILE_BYTES) fail('JOURNAL_TOO_LARGE');
  return serialized;
}

export class BrickkenJournal {
  constructor({ directory = path.join(PROJECT_ROOT, 'data', 'brickken-journal'), now = () => new Date().toISOString() } = {}) {
    if (typeof now !== 'function') fail('TIME');
    this.now = () => iso(now());
    this.directory = boundedJournalPath(directory);
    fs.mkdirSync(this.directory, { recursive: true });
    boundedJournalPath(this.directory);
    this.file = boundedJournalPath(path.join(this.directory, 'journal.json'));
    this.lock = boundedJournalPath(path.join(this.directory, 'journal.lock'));
    if (fs.lstatSync(this.file, { throwIfNoEntry: false })) this.#read();
    else this.#writeTransaction(() => null, true);
  }

  get(operationId) {
    identifier(operationId);
    const record = this.#read().operations.find(item => item.operationId === operationId);
    if (!record) fail('OPERATION_NOT_FOUND');
    return structuredClone(record);
  }

  list() { return structuredClone(this.#read().operations); }

  createPending(binding) {
    shape(binding, ['operationId', 'operationKind', 'txId', 'preparationHash', 'transaction', 'createdAt']);
    const candidate = {
      operationId: identifier(binding.operationId),
      operationKind: binding.operationKind,
      txId: identifier(binding.txId),
      preparationHash: typeof binding.preparationHash === 'string' ? binding.preparationHash : '',
      transaction: transaction(binding.transaction),
      createdAt: iso(binding.createdAt), state: 'pending', updatedAt: binding.createdAt,
      signed: null, broadcast: null, confirmation: null, semanticVerification: null
    };
    if (!['setAction', 'approve', 'grant', 'execute', 'revoke'].includes(candidate.operationKind)) fail('OPERATION_KIND');
    if (!/^[a-f0-9]{64}$/.test(candidate.preparationHash)) fail('HASH');
    return this.#writeTransaction(document => {
      const duplicate = document.operations.find(item => item.operationId === candidate.operationId);
      if (duplicate) {
        const existingBinding = {
          operationId: duplicate.operationId, operationKind: duplicate.operationKind, txId: duplicate.txId, preparationHash: duplicate.preparationHash,
          transaction: duplicate.transaction, createdAt: duplicate.createdAt
        };
        const candidateBinding = {
          operationId: candidate.operationId, operationKind: candidate.operationKind, txId: candidate.txId, preparationHash: candidate.preparationHash,
          transaction: candidate.transaction, createdAt: candidate.createdAt
        };
        if (!same(existingBinding, candidateBinding)) fail('OPERATION_ID_CONFLICT');
        return duplicate;
      }
      if (document.operations.some(item => item.txId === candidate.txId)) fail('TX_ID_CONFLICT');
      document.operations.push(candidate);
      return candidate;
    });
  }

  recordSigned(operationId, signedInput, verifySignedTransaction) {
    identifier(operationId);
    shape(signedInput, ['source', 'signedTransaction', 'signedAt']);
    if (signedInput.source !== 'injected-fixture' || typeof verifySignedTransaction !== 'function') fail('SIGNED_VERIFIER_REQUIRED');
    const bytes = exactHex(signedInput.signedTransaction);
    const verified = verifySignedTransaction(bytes);
    shape(verified, ['transactionHash', 'transaction'], 'SIGNED_VERIFICATION');
    const decoded = transaction(verified.transaction);
    const ethereumTransactionHash = hash32(verified.transactionHash, 'ETHEREUM_TRANSACTION_HASH');
    const signed = {
      source: signedInput.source,
      signedTransaction: bytes,
      ethereumTransactionHash,
      signedBytesSha256: sha256(Buffer.from(bytes.slice(2), 'hex')),
      decodedTransaction: decoded,
      signedAt: iso(signedInput.signedAt)
    };
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      if (!same(record.transaction, decoded)) fail('SIGNED_TRANSACTION_MISMATCH');
      if (record.signed) {
        if (same(record.signed, signed)) return record;
        fail('UNRESOLVED_SIGNATURE');
      }
      if (record.state !== 'pending') fail('STATE_TRANSITION');
      if (document.operations.some(item => item.operationId !== record.operationId && item.signed !== null &&
          item.transaction.chainId === record.transaction.chainId && item.transaction.from === record.transaction.from &&
          item.transaction.nonce === record.transaction.nonce)) fail('NONCE_ALREADY_RESERVED');
      record.signed = signed; record.state = 'signed'; record.updatedAt = signed.signedAt;
      return record;
    });
  }

  recordBroadcast(operationId, signedTransaction, { result, attemptedAt }) {
    identifier(operationId);
    if (!['accepted', 'uncertain'].includes(result)) fail('BROADCAST_RESULT');
    const bytes = exactHex(signedTransaction);
    const at = iso(attemptedAt);
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      this.#requireSameBytes(record, bytes);
      if (!['signed', 'broadcast', 'uncertain'].includes(record.state)) fail('STATE_TRANSITION');
      if (record.broadcast && record.broadcast.result === 'nonce-conflict') fail('NONCE_CONFLICT');
      record.broadcast = {
        attempts: (record.broadcast?.attempts ?? 0) + 1,
        result, lastAttemptAt: at, lastObservationAt: record.broadcast?.lastObservationAt ?? null
      };
      record.state = result === 'accepted' ? 'broadcast' : 'uncertain'; record.updatedAt = at;
      return record;
    });
  }

  authorizeIdenticalResend(operationId, signedTransaction) {
    const record = this.get(operationId);
    if (!['broadcast', 'uncertain'].includes(record.state) || record.broadcast?.result === 'nonce-conflict') fail('RESEND_BLOCKED');
    this.#requireSameBytes(record, exactHex(signedTransaction));
    return Object.freeze({
      operationId: record.operationId,
      transactionHash: record.signed.ethereumTransactionHash,
      signedTransaction: record.signed.signedTransaction,
      identicalBytesOnly: true
    });
  }

  recoverUncertain(operationId, observation) {
    shape(observation, ['observedAt', 'transactionByHash', 'transactionByNonce']);
    const at = iso(observation.observedAt);
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      if (!['broadcast', 'uncertain'].includes(record.state)) fail('RECOVERY_NOT_ALLOWED');
      const expectedHash = record.signed.ethereumTransactionHash;
      const hashResult = observation.transactionByHash;
      const nonceResult = observation.transactionByNonce;
      if (nonceResult !== null) {
        shape(nonceResult, ['transactionHash', 'nonce']);
        const nonceHash = hash32(nonceResult.transactionHash);
        if (uint(nonceResult.nonce) !== record.transaction.nonce) fail('RECOVERY_MISMATCH');
        if (nonceHash !== expectedHash) {
          record.broadcast.result = 'nonce-conflict'; record.broadcast.lastObservationAt = at;
          record.state = 'uncertain'; record.updatedAt = at;
          return record;
        }
      }
      if (hashResult !== null) {
        shape(hashResult, ['transactionHash', 'nonce']);
        if (hash32(hashResult.transactionHash) !== expectedHash || uint(hashResult.nonce) !== record.transaction.nonce) fail('RECOVERY_MISMATCH');
        record.broadcast.result = 'recovered-by-hash'; record.broadcast.lastObservationAt = at;
        record.state = 'broadcast'; record.updatedAt = at;
        return record;
      }
      if (nonceResult !== null) {
        record.broadcast.result = 'recovered-by-hash'; record.broadcast.lastObservationAt = at;
        record.state = 'broadcast'; record.updatedAt = at;
        return record;
      }
      record.broadcast.result = 'uncertain'; record.broadcast.lastObservationAt = at;
      record.state = 'uncertain'; record.updatedAt = at;
      return record;
    });
  }

  confirm(operationId, confirmationInput) {
    shape(confirmationInput, ['transactionHash', 'blockNumber', 'blockHash', 'confirmations', 'checkedAt']);
    const confirmation = {
      transactionHash: hash32(confirmationInput.transactionHash), blockNumber: uint(confirmationInput.blockNumber),
      blockHash: hash32(confirmationInput.blockHash), confirmations: confirmationInput.confirmations,
      checkedAt: iso(confirmationInput.checkedAt)
    };
    if (!Number.isSafeInteger(confirmation.confirmations) || confirmation.confirmations < 1) fail('CONFIRMATIONS');
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      if (!['broadcast', 'uncertain', 'confirmed'].includes(record.state)) fail('STATE_TRANSITION');
      if (record.broadcast?.result === 'nonce-conflict') fail('NONCE_CONFLICT');
      if (confirmation.transactionHash !== record.signed.ethereumTransactionHash) fail('TRANSACTION_HASH_MISMATCH');
      if (record.confirmation && !same(record.confirmation, confirmation)) fail('CONFIRMATION_CONFLICT');
      record.confirmation = confirmation; record.state = 'confirmed'; record.updatedAt = confirmation.checkedAt;
      return record;
    });
  }

  recheckConfirmation(operationId, observation) {
    shape(observation, ['transactionHash', 'blockNumber', 'blockHash', 'checkedAt']);
    const at = iso(observation.checkedAt);
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      if (!['confirmed', 'semantically_verified'].includes(record.state) || !record.confirmation) fail('CONFIRMATION_REQUIRED');
      const matches = hash32(observation.transactionHash) === record.confirmation.transactionHash &&
        uint(observation.blockNumber) === record.confirmation.blockNumber &&
        hash32(observation.blockHash) === record.confirmation.blockHash;
      if (matches) {
        record.confirmation.checkedAt = at; record.updatedAt = at;
        return record;
      }
      record.confirmation = null; record.semanticVerification = null;
      record.broadcast.result = 'uncertain'; record.broadcast.lastObservationAt = at;
      record.state = 'uncertain'; record.updatedAt = at;
      return record;
    });
  }

  markSemanticallyVerified(operationId, postcheck) {
    shape(postcheck, [
      'schemaVersion', 'kind', 'operationKind', 'transactionHash', 'blockNumber',
      'blockHash', 'verified', 'checks', 'scope', 'observedAt'
    ], 'POSTCHECK');
    if (!isVerifiedBrickkenPostcheck(postcheck) || postcheck.schemaVersion !== 1 || postcheck.kind !== 'brickken-semantic-postcheck' ||
      postcheck.verified !== true || !Array.isArray(postcheck.checks)) fail('POSTCHECK');
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      if (record.state !== 'confirmed' || !record.confirmation) fail('CONFIRMATION_REQUIRED');
      if (postcheck.operationKind !== record.operationKind) fail('POSTCHECK_KIND');
      if (hash32(postcheck.transactionHash) !== record.confirmation.transactionHash ||
          uint(postcheck.blockNumber) !== record.confirmation.blockNumber ||
          hash32(postcheck.blockHash) !== record.confirmation.blockHash) fail('POSTCHECK_IDENTITY');
      const semantic = {
        operationKind: postcheck.operationKind,
        transactionHash: record.confirmation.transactionHash,
        blockNumber: record.confirmation.blockNumber,
        blockHash: record.confirmation.blockHash,
        postcheckSha256: sha256(Buffer.from(canonical(postcheck), 'utf8')),
        verifiedAt: this.now()
      };
      record.semanticVerification = semantic; record.state = 'semantically_verified'; record.updatedAt = semantic.verifiedAt;
      return record;
    });
  }

  #find(document, operationId) {
    const record = document.operations.find(item => item.operationId === operationId);
    if (!record) fail('OPERATION_NOT_FOUND');
    return record;
  }
  #requireSameBytes(record, bytes) {
    if (!record.signed || record.signed.signedTransaction !== bytes ||
        record.signed.signedBytesSha256 !== sha256(Buffer.from(bytes.slice(2), 'hex'))) fail('SIGNED_BYTES_MISMATCH');
  }
  #read() {
    boundedJournalPath(this.file);
    try {
      const stat = fs.statSync(this.file);
      if (!stat.isFile() || stat.size > MAX_FILE_BYTES) fail('JOURNAL_CORRUPT');
      return validateDocument(JSON.parse(fs.readFileSync(this.file, 'utf8')));
    } catch (error) {
      if (error instanceof BrickkenJournalError) throw error;
      fail('JOURNAL_CORRUPT');
    }
  }
  #writeTransaction(change, initialize = false) {
    boundedJournalPath(this.lock); boundedJournalPath(this.file);
    let lock;
    try { lock = fs.openSync(this.lock, 'wx'); }
    catch { fail('JOURNAL_BUSY'); }
    let temporary;
    try {
      fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, at: this.now() }));
      const exists = fs.existsSync(this.file);
      const document = exists ? this.#read() : newDocument();
      if (!exists && !initialize) fail('JOURNAL_CORRUPT');
      if (exists && initialize) return null;
      const result = change(document);
      document.selfHash = documentHash(document);
      const serialized = serializeDocument(document);
      temporary = boundedJournalPath(path.join(this.directory, `journal-${randomUUID()}.tmp`));
      const descriptor = fs.openSync(temporary, 'wx');
      try {
        fs.writeFileSync(descriptor, serialized);
        fs.fsyncSync(descriptor);
      } finally { fs.closeSync(descriptor); }
      this.#atomicRename(temporary, this.file); temporary = null;
      return structuredClone(result);
    } finally {
      if (temporary && fs.existsSync(temporary)) fs.unlinkSync(temporary);
      if (lock !== undefined) fs.closeSync(lock);
      if (fs.existsSync(this.lock)) fs.unlinkSync(this.lock);
    }
  }
  #atomicRename(source, destination) {
    for (let attempt = 1; attempt <= 25; attempt++) {
      try { fs.renameSync(source, destination); return; }
      catch (error) {
        if (!['EPERM', 'EACCES', 'EBUSY'].includes(error?.code) || attempt === 25) fail('JOURNAL_BUSY');
        Atomics.wait(WAIT, 0, 0, 10);
      }
    }
  }
}

// Live transaction journal, schemaVersion 2. It keeps the offline state model
// and adds what a real Sepolia run needs: the route, the Brickken API txId kept
// apart from the Ethereum transaction hash, a closed live signer source, a
// confirmation agreed by two RPC sources and a terminal reverted state. It
// performs no HTTP, signing or broadcast; the adapter supplies observations.
export const LIVE_JOURNAL_STATES = Object.freeze([...JOURNAL_STATES, 'reverted']);
export const LIVE_OPERATION_KINDS = Object.freeze(['setAction', 'approve', 'grant', 'execute', 'revoke', 'approveReset']);
export const LIVE_ROUTES = Object.freeze(['brickken-api', 'sepolia-rpc']);
export const LIVE_SIGNER_SOURCE = 'live-signer-v1';
// A live holder of the journal lock makes a writer wait up to about one second.
const LIVE_LOCK_ATTEMPTS = 100;

const LIVE_BINDING_KEYS = ['operationId', 'operationKind', 'route', 'apiTxId', 'preparationHash', 'transaction', 'createdAt'];
const LIVE_RECORD_KEYS = [
  ...LIVE_BINDING_KEYS, 'state', 'updatedAt', 'signed', 'broadcast', 'confirmation', 'semanticVerification'
];
const LIVE_SIGNED_KEYS = [
  'source', 'approvalSha256', 'signedTransaction', 'ethereumTransactionHash', 'signedBytesSha256',
  'decodedTransaction', 'signedAt'
];
const LIVE_BROADCAST_KEYS = ['attempts', 'result', 'relayTransactionHash', 'lastAttemptAt', 'lastObservationAt'];
// attemptsAt keeps the time of the most recent attempts so a resend budget can
// be bounded per time window while `attempts` stays the complete audit count.
const LIVE_BROADCAST_OPTIONAL_KEYS = ['attemptsAt'];
const MAX_ATTEMPT_TIMES = 64;
const LIVE_CONFIRMATION_KEYS = [
  'transactionHash', 'blockNumber', 'blockHash', 'secondaryBlockHash', 'receiptStatus', 'confirmations', 'checkedAt'
];
const LIVE_RECHECK_KEYS = ['transactionHash', 'blockNumber', 'blockHash', 'secondaryBlockHash', 'confirmations', 'checkedAt'];
const LIVE_SEMANTIC_KEYS = ['postcheckKind', 'transactionHash', 'blockNumber', 'blockHash', 'postcheckSha256', 'verifiedAt'];
const LIVE_POSTCHECK_KEYS = [
  'schemaVersion', 'kind', 'operationKind', 'transactionHash', 'blockNumber',
  'blockHash', 'verified', 'checks', 'scope', 'observedAt'
];

// approve(0) is verified by the same ERC-20 approval postcheck as approve.
export function livePostcheckKind(operationKind) {
  if (!LIVE_OPERATION_KINDS.includes(operationKind)) fail('OPERATION_KIND');
  return operationKind === 'approveReset' ? 'approve' : operationKind;
}
function sha64(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail('HASH');
  return value;
}
function liveApiTxId(route, value) {
  if (!LIVE_ROUTES.includes(route)) fail('ROUTE');
  // A local identifier is never stored as a Brickken txId.
  if (route === 'sepolia-rpc') {
    if (value !== null) fail('API_TX_ID_ROUTE');
    return null;
  }
  return identifier(value);
}
function validateLiveSigned(value, expected) {
  shape(value, LIVE_SIGNED_KEYS, 'JOURNAL_CORRUPT');
  if (value.source !== LIVE_SIGNER_SOURCE || typeof value.approvalSha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(value.approvalSha256)) fail('JOURNAL_CORRUPT');
  const bytes = exactHex(value.signedTransaction);
  const decoded = transaction(value.decodedTransaction);
  if (!same(decoded, expected) || bytes !== value.signedTransaction ||
      value.signedBytesSha256 !== sha256(Buffer.from(bytes.slice(2), 'hex')) ||
      hash32(value.ethereumTransactionHash) !== value.ethereumTransactionHash) fail('JOURNAL_CORRUPT');
  iso(value.signedAt);
  return value;
}
function validateLiveBroadcast(value, signed) {
  shapeWithOptional(value, LIVE_BROADCAST_KEYS, LIVE_BROADCAST_OPTIONAL_KEYS, 'JOURNAL_CORRUPT');
  if (!signed || !Number.isSafeInteger(value.attempts) || value.attempts < 1 ||
      !['accepted', 'uncertain', 'recovered-by-hash', 'nonce-conflict'].includes(value.result)) fail('JOURNAL_CORRUPT');
  if (Object.hasOwn(value, 'attemptsAt')) {
    if (!Array.isArray(value.attemptsAt) || value.attemptsAt.length > MAX_ATTEMPT_TIMES ||
        value.attemptsAt.length > value.attempts) fail('JOURNAL_CORRUPT');
    for (const at of value.attemptsAt) iso(at);
  }
  if (value.relayTransactionHash !== null && hash32(value.relayTransactionHash) !== value.relayTransactionHash) fail('JOURNAL_CORRUPT');
  // A relay that reported a different hash never counts as an accepted broadcast.
  if (value.result === 'accepted' && value.relayTransactionHash !== null &&
      value.relayTransactionHash !== signed.ethereumTransactionHash) fail('JOURNAL_CORRUPT');
  iso(value.lastAttemptAt);
  if (value.lastObservationAt !== null) iso(value.lastObservationAt);
  return value;
}
function validateLiveConfirmation(value, signed) {
  shape(value, LIVE_CONFIRMATION_KEYS, 'JOURNAL_CORRUPT');
  if (!signed || value.transactionHash !== signed.ethereumTransactionHash ||
      hash32(value.blockHash) !== value.blockHash || value.secondaryBlockHash !== value.blockHash ||
      ![0, 1].includes(value.receiptStatus) ||
      !Number.isSafeInteger(value.confirmations) || value.confirmations < 1) fail('JOURNAL_CORRUPT');
  uint(value.blockNumber); iso(value.checkedAt);
  return value;
}
function validateLiveSemantic(value, confirmation, operationKind) {
  shape(value, LIVE_SEMANTIC_KEYS, 'JOURNAL_CORRUPT');
  if (!confirmation || value.postcheckKind !== livePostcheckKind(operationKind) ||
      value.transactionHash !== confirmation.transactionHash || value.blockNumber !== confirmation.blockNumber ||
      value.blockHash !== confirmation.blockHash || !/^[a-f0-9]{64}$/.test(value.postcheckSha256)) fail('JOURNAL_CORRUPT');
  iso(value.verifiedAt);
  return value;
}
function validateLiveRecord(value) {
  shape(value, LIVE_RECORD_KEYS, 'JOURNAL_CORRUPT');
  identifier(value.operationId);
  if (!LIVE_OPERATION_KINDS.includes(value.operationKind) || !LIVE_ROUTES.includes(value.route)) fail('JOURNAL_CORRUPT');
  if (value.route === 'brickken-api'
    ? (typeof value.apiTxId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value.apiTxId))
    : value.apiTxId !== null) fail('JOURNAL_CORRUPT');
  if (typeof value.preparationHash !== 'string' || !/^[a-f0-9]{64}$/.test(value.preparationHash)) fail('JOURNAL_CORRUPT');
  const tx = transaction(value.transaction);
  iso(value.createdAt); iso(value.updatedAt);
  if (!LIVE_JOURNAL_STATES.includes(value.state)) fail('JOURNAL_CORRUPT');
  const signed = value.signed === null ? null : validateLiveSigned(value.signed, tx);
  const broadcast = value.broadcast === null ? null : validateLiveBroadcast(value.broadcast, signed);
  const confirmation = value.confirmation === null ? null : validateLiveConfirmation(value.confirmation, signed);
  const semantic = value.semanticVerification === null
    ? null : validateLiveSemantic(value.semanticVerification, confirmation, value.operationKind);
  const requirements = {
    pending: [!signed, !broadcast, !confirmation, !semantic],
    signed: [signed, !broadcast, !confirmation, !semantic],
    broadcast: [signed, broadcast, ['accepted', 'recovered-by-hash'].includes(broadcast?.result), !confirmation, !semantic],
    uncertain: [signed, broadcast, ['uncertain', 'nonce-conflict'].includes(broadcast?.result), !confirmation, !semantic],
    confirmed: [signed, broadcast, confirmation?.receiptStatus === 1, !semantic],
    reverted: [signed, broadcast, confirmation?.receiptStatus === 0, !semantic],
    semantically_verified: [signed, broadcast, confirmation?.receiptStatus === 1, semantic]
  }[value.state];
  if (!requirements.every(Boolean)) fail('JOURNAL_CORRUPT');
  return value;
}
function liveDocumentHash(document) {
  return sha256(Buffer.from(canonical({
    schemaVersion: document.schemaVersion, kind: document.kind, operations: document.operations
  }), 'utf8'));
}
function validateLiveDocument(value) {
  shape(value, ['schemaVersion', 'kind', 'operations', 'selfHash'], 'JOURNAL_CORRUPT');
  if (value.schemaVersion !== 2 || value.kind !== 'mandate-desk-live-journal' || !Array.isArray(value.operations) ||
      value.operations.length > 10000 || typeof value.selfHash !== 'string' || !/^[a-f0-9]{64}$/.test(value.selfHash) ||
      liveDocumentHash(value) !== value.selfHash) fail('JOURNAL_CORRUPT');
  const operationIds = new Set();
  const apiTxIds = new Set();
  const signedNonces = new Set();
  for (const record of value.operations) {
    validateLiveRecord(record);
    if (operationIds.has(record.operationId)) fail('JOURNAL_CORRUPT');
    operationIds.add(record.operationId);
    if (record.apiTxId !== null) {
      if (apiTxIds.has(record.apiTxId)) fail('JOURNAL_CORRUPT');
      apiTxIds.add(record.apiTxId);
    }
    if (record.signed) {
      const key = `${record.transaction.chainId}:${record.transaction.from}:${record.transaction.nonce}`;
      if (signedNonces.has(key)) fail('JOURNAL_CORRUPT');
      signedNonces.add(key);
    }
  }
  return value;
}
function newLiveDocument() {
  const value = { schemaVersion: 2, kind: 'mandate-desk-live-journal', operations: [], selfHash: '' };
  value.selfHash = liveDocumentHash(value);
  return value;
}
function serializeLiveDocument(value) {
  validateLiveDocument(value);
  const serialized = JSON.stringify(value, null, 2);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_FILE_BYTES) fail('JOURNAL_TOO_LARGE');
  return serialized;
}
function pickBinding(record) {
  return Object.fromEntries(LIVE_BINDING_KEYS.map(key => [key, record[key]]));
}

export class LiveBrickkenJournal {
  constructor({ directory, now = () => new Date().toISOString() } = {}) {
    if (typeof now !== 'function') fail('TIME');
    if (typeof directory !== 'string') fail('PATH_SCOPE');
    this.now = () => iso(now());
    this.directory = boundedJournalPath(directory);
    fs.mkdirSync(this.directory, { recursive: true });
    boundedJournalPath(this.directory);
    this.file = boundedJournalPath(path.join(this.directory, 'live-journal.json'));
    this.lock = boundedJournalPath(path.join(this.directory, 'live-journal.lock'));
    if (fs.lstatSync(this.file, { throwIfNoEntry: false })) this.#read();
    else this.#writeTransaction(() => null, true);
  }

  get(operationId) {
    identifier(operationId);
    const record = this.#read().operations.find(item => item.operationId === operationId);
    if (!record) fail('OPERATION_NOT_FOUND');
    return structuredClone(record);
  }

  find(operationId) {
    identifier(operationId);
    const record = this.#read().operations.find(item => item.operationId === operationId);
    return record ? structuredClone(record) : null;
  }

  list() { return structuredClone(this.#read().operations); }

  createPending(binding) {
    shape(binding, LIVE_BINDING_KEYS);
    const candidate = {
      operationId: identifier(binding.operationId),
      operationKind: LIVE_OPERATION_KINDS.includes(binding.operationKind) ? binding.operationKind : fail('OPERATION_KIND'),
      route: binding.route,
      apiTxId: liveApiTxId(binding.route, binding.apiTxId),
      preparationHash: sha64(binding.preparationHash),
      transaction: transaction(binding.transaction),
      createdAt: iso(binding.createdAt), state: 'pending', updatedAt: binding.createdAt,
      signed: null, broadcast: null, confirmation: null, semanticVerification: null
    };
    return this.#writeTransaction(document => {
      const duplicate = document.operations.find(item => item.operationId === candidate.operationId);
      if (duplicate) {
        if (!same(pickBinding(duplicate), pickBinding(candidate))) fail('OPERATION_ID_CONFLICT');
        return duplicate;
      }
      if (candidate.apiTxId !== null && document.operations.some(item => item.apiTxId === candidate.apiTxId)) {
        fail('TX_ID_CONFLICT');
      }
      document.operations.push(candidate);
      return candidate;
    });
  }

  // An unsigned preparation can be replaced, for example when its nonce went
  // stale before signing. Nothing was signed, so no transaction identity is lost.
  replacePending(binding) {
    shape(binding, LIVE_BINDING_KEYS);
    const candidate = {
      operationId: identifier(binding.operationId),
      operationKind: LIVE_OPERATION_KINDS.includes(binding.operationKind) ? binding.operationKind : fail('OPERATION_KIND'),
      route: binding.route,
      apiTxId: liveApiTxId(binding.route, binding.apiTxId),
      preparationHash: sha64(binding.preparationHash),
      transaction: transaction(binding.transaction),
      createdAt: iso(binding.createdAt), state: 'pending', updatedAt: binding.createdAt,
      signed: null, broadcast: null, confirmation: null, semanticVerification: null
    };
    return this.#writeTransaction(document => {
      const index = document.operations.findIndex(item => item.operationId === candidate.operationId);
      if (index === -1) fail('OPERATION_NOT_FOUND');
      const record = document.operations[index];
      if (record.state !== 'pending' || record.signed !== null) fail('STATE_TRANSITION');
      if (record.operationKind !== candidate.operationKind || record.route !== candidate.route) fail('OPERATION_ID_CONFLICT');
      if (candidate.apiTxId !== null && document.operations.some(item => item.operationId !== candidate.operationId &&
          item.apiTxId === candidate.apiTxId)) fail('TX_ID_CONFLICT');
      document.operations[index] = candidate;
      return candidate;
    });
  }

  // verifySignedTransaction has the offline journal's contract: it decodes and
  // Keccak-hashes the exact bytes with the pinned Ethereum library and returns
  // { transactionHash, transaction }. The journal compares every decoded field.
  recordSigned(operationId, signedInput, verifySignedTransaction) {
    identifier(operationId);
    shape(signedInput, ['source', 'approvalSha256', 'signedTransaction', 'signedAt']);
    if (signedInput.source !== LIVE_SIGNER_SOURCE || typeof verifySignedTransaction !== 'function') {
      fail('SIGNED_VERIFIER_REQUIRED');
    }
    const approvalSha256 = sha64(signedInput.approvalSha256);
    const bytes = exactHex(signedInput.signedTransaction);
    const verified = verifySignedTransaction(bytes);
    shape(verified, ['transactionHash', 'transaction'], 'SIGNED_VERIFICATION');
    const decoded = transaction(verified.transaction);
    const signed = {
      source: LIVE_SIGNER_SOURCE,
      approvalSha256,
      signedTransaction: bytes,
      ethereumTransactionHash: hash32(verified.transactionHash, 'ETHEREUM_TRANSACTION_HASH'),
      signedBytesSha256: sha256(Buffer.from(bytes.slice(2), 'hex')),
      decodedTransaction: decoded,
      signedAt: iso(signedInput.signedAt)
    };
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      if (!same(record.transaction, decoded)) fail('SIGNED_TRANSACTION_MISMATCH');
      if (record.signed) {
        if (record.signed.signedTransaction === signed.signedTransaction &&
            record.signed.approvalSha256 === signed.approvalSha256) return record;
        fail('UNRESOLVED_SIGNATURE');
      }
      if (record.state !== 'pending') fail('STATE_TRANSITION');
      if (document.operations.some(item => item.operationId !== record.operationId && item.signed !== null &&
          item.transaction.chainId === record.transaction.chainId && item.transaction.from === record.transaction.from &&
          item.transaction.nonce === record.transaction.nonce)) fail('NONCE_ALREADY_RESERVED');
      record.signed = signed; record.state = 'signed'; record.updatedAt = signed.signedAt;
      return record;
    });
  }

  recordBroadcast(operationId, signedTransaction, input) {
    identifier(operationId);
    shape(input, ['result', 'attemptedAt', 'relayTransactionHash']);
    if (!['accepted', 'uncertain'].includes(input.result)) fail('BROADCAST_RESULT');
    const bytes = exactHex(signedTransaction);
    const at = iso(input.attemptedAt);
    const relay = input.relayTransactionHash === null ? null : hash32(input.relayTransactionHash);
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      this.#requireSameBytes(record, bytes);
      if (!['signed', 'broadcast', 'uncertain'].includes(record.state)) fail('STATE_TRANSITION');
      if (record.broadcast?.result === 'nonce-conflict') fail('NONCE_CONFLICT');
      const storedRelay = relay ?? record.broadcast?.relayTransactionHash ?? null;
      const mismatch = storedRelay !== null && storedRelay !== record.signed.ethereumTransactionHash;
      const result = mismatch || input.result === 'uncertain' ? 'uncertain' : 'accepted';
      record.broadcast = {
        attempts: (record.broadcast?.attempts ?? 0) + 1,
        result: record.state === 'broadcast' && record.broadcast.result === 'recovered-by-hash' && !mismatch
          ? 'recovered-by-hash' : result,
        relayTransactionHash: storedRelay,
        lastAttemptAt: at,
        lastObservationAt: record.broadcast?.lastObservationAt ?? null,
        attemptsAt: [...(record.broadcast?.attemptsAt ?? []), at].slice(-MAX_ATTEMPT_TIMES)
      };
      record.state = ['accepted', 'recovered-by-hash'].includes(record.broadcast.result) ? 'broadcast' : 'uncertain';
      record.updatedAt = at;
      return record;
    });
  }

  authorizeIdenticalResend(operationId, signedTransaction) {
    const record = this.get(operationId);
    if (!['broadcast', 'uncertain'].includes(record.state) || record.broadcast?.result === 'nonce-conflict') fail('RESEND_BLOCKED');
    this.#requireSameBytes(record, exactHex(signedTransaction));
    return Object.freeze({
      operationId: record.operationId,
      transactionHash: record.signed.ethereumTransactionHash,
      signedTransaction: record.signed.signedTransaction,
      identicalBytesOnly: true
    });
  }

  // transactionByHash must be null only when neither RPC source returned the
  // exact signed hash. latestNonce is the signer's mined nonce count.
  recoverUncertain(operationId, observation) {
    shape(observation, ['observedAt', 'transactionByHash', 'latestNonce']);
    const at = iso(observation.observedAt);
    const latestNonce = uint(observation.latestNonce);
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      if (!['broadcast', 'uncertain'].includes(record.state)) fail('RECOVERY_NOT_ALLOWED');
      const byHash = observation.transactionByHash;
      if (byHash !== null) {
        shape(byHash, ['transactionHash', 'nonce', 'from']);
        if (hash32(byHash.transactionHash) !== record.signed.ethereumTransactionHash ||
            uint(byHash.nonce) !== record.transaction.nonce || address(byHash.from) !== record.transaction.from) {
          fail('RECOVERY_MISMATCH');
        }
        // Chain evidence of the exact hash outranks an earlier inference; an
        // accepted broadcast that is now observed simply stays accepted.
        if (record.broadcast.result !== 'accepted') record.broadcast.result = 'recovered-by-hash';
        record.state = 'broadcast';
      } else if (BigInt(latestNonce) > BigInt(record.transaction.nonce)) {
        record.broadcast.result = 'nonce-conflict';
        record.state = 'uncertain';
      }
      record.broadcast.lastObservationAt = at; record.updatedAt = at;
      return record;
    });
  }

  confirm(operationId, input) {
    shape(input, LIVE_CONFIRMATION_KEYS);
    const confirmation = {
      transactionHash: hash32(input.transactionHash), blockNumber: uint(input.blockNumber),
      blockHash: hash32(input.blockHash), secondaryBlockHash: hash32(input.secondaryBlockHash),
      receiptStatus: input.receiptStatus, confirmations: input.confirmations, checkedAt: iso(input.checkedAt)
    };
    if (![0, 1].includes(confirmation.receiptStatus)) fail('RECEIPT_STATUS');
    if (!Number.isSafeInteger(confirmation.confirmations) || confirmation.confirmations < 1) fail('CONFIRMATIONS');
    if (confirmation.secondaryBlockHash !== confirmation.blockHash) fail('SOURCE_DISAGREEMENT');
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      if (!['broadcast', 'uncertain', 'confirmed', 'reverted'].includes(record.state)) fail('STATE_TRANSITION');
      if (confirmation.transactionHash !== record.signed.ethereumTransactionHash) fail('TRANSACTION_HASH_MISMATCH');
      if (record.confirmation) {
        const { checkedAt: _checked, confirmations: _count, ...existing } = record.confirmation;
        const { checkedAt: _incomingChecked, confirmations: _incomingCount, ...incoming } = confirmation;
        if (!same(existing, incoming)) fail('CONFIRMATION_CONFLICT');
      }
      if (record.broadcast.result !== 'accepted') record.broadcast.result = 'recovered-by-hash';
      record.confirmation = confirmation;
      record.state = confirmation.receiptStatus === 1 ? 'confirmed' : 'reverted';
      record.updatedAt = confirmation.checkedAt;
      return record;
    });
  }

  // A different block hash at the recorded height from either source is a
  // reorganisation: the confirmation and any semantic result are withdrawn.
  recheckConfirmation(operationId, observation) {
    shape(observation, LIVE_RECHECK_KEYS);
    const at = iso(observation.checkedAt);
    if (!Number.isSafeInteger(observation.confirmations) || observation.confirmations < 1) fail('CONFIRMATIONS');
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      if (!['confirmed', 'reverted', 'semantically_verified'].includes(record.state) || !record.confirmation) {
        fail('CONFIRMATION_REQUIRED');
      }
      const matches = hash32(observation.transactionHash) === record.confirmation.transactionHash &&
        uint(observation.blockNumber) === record.confirmation.blockNumber &&
        hash32(observation.blockHash) === record.confirmation.blockHash &&
        hash32(observation.secondaryBlockHash) === record.confirmation.blockHash;
      if (matches) {
        // The current depth replaces the stored one: a count is never kept from an earlier, deeper reading.
        record.confirmation.checkedAt = at;
        record.confirmation.confirmations = observation.confirmations;
        record.updatedAt = at;
        return record;
      }
      record.confirmation = null; record.semanticVerification = null;
      record.broadcast.result = 'uncertain'; record.broadcast.lastObservationAt = at;
      record.state = 'uncertain'; record.updatedAt = at;
      return record;
    });
  }

  markSemanticallyVerified(operationId, postcheck) {
    shape(postcheck, LIVE_POSTCHECK_KEYS, 'POSTCHECK');
    if (!isVerifiedBrickkenPostcheck(postcheck) || postcheck.schemaVersion !== 1 ||
        postcheck.kind !== 'brickken-semantic-postcheck' || postcheck.verified !== true) fail('POSTCHECK');
    return this.#writeTransaction(document => {
      const record = this.#find(document, operationId);
      if (record.state !== 'confirmed' || !record.confirmation) fail('CONFIRMATION_REQUIRED');
      if (postcheck.operationKind !== livePostcheckKind(record.operationKind)) fail('POSTCHECK_KIND');
      if (hash32(postcheck.transactionHash) !== record.confirmation.transactionHash ||
          uint(postcheck.blockNumber) !== record.confirmation.blockNumber ||
          hash32(postcheck.blockHash) !== record.confirmation.blockHash) fail('POSTCHECK_IDENTITY');
      const semantic = {
        postcheckKind: postcheck.operationKind,
        transactionHash: record.confirmation.transactionHash,
        blockNumber: record.confirmation.blockNumber,
        blockHash: record.confirmation.blockHash,
        postcheckSha256: sha256(Buffer.from(canonical(postcheck), 'utf8')),
        verifiedAt: this.now()
      };
      record.semanticVerification = semantic; record.state = 'semantically_verified'; record.updatedAt = semantic.verifiedAt;
      return record;
    });
  }

  #find(document, operationId) {
    const record = document.operations.find(item => item.operationId === operationId);
    if (!record) fail('OPERATION_NOT_FOUND');
    return record;
  }
  #requireSameBytes(record, bytes) {
    if (!record.signed || record.signed.signedTransaction !== bytes ||
        record.signed.signedBytesSha256 !== sha256(Buffer.from(bytes.slice(2), 'hex'))) fail('SIGNED_BYTES_MISMATCH');
  }
  #read() {
    boundedJournalPath(this.file);
    try {
      const stat = fs.statSync(this.file);
      if (!stat.isFile() || stat.size > MAX_FILE_BYTES) fail('JOURNAL_CORRUPT');
      return validateLiveDocument(JSON.parse(fs.readFileSync(this.file, 'utf8')));
    } catch (error) {
      if (error instanceof BrickkenJournalError) throw error;
      fail('JOURNAL_CORRUPT');
    }
  }
  // The short write lock follows the shared live lock protocol: a live holder
  // makes the write wait and then fail JOURNAL_BUSY, a holder whose process is
  // gone is taken over, and unreadable lock content stops with its own code.
  #writeTransaction(change, initialize = false) {
    boundedJournalPath(this.lock); boundedJournalPath(this.file);
    let lease;
    try {
      lease = acquireLiveLock(this.lock, {
        holder: { purpose: 'live-journal-write' }, now: () => Date.parse(this.now()),
        attempts: LIVE_LOCK_ATTEMPTS, waitMs: 10, busyCode: 'JOURNAL_BUSY'
      });
    } catch (error) {
      if (!(error instanceof LiveLockError)) throw error;
      fail(error.code === 'LOCK_INVALID' ? 'JOURNAL_LOCK_INVALID' : error.code === 'LOCK_CONFLICT' ? 'JOURNAL_LOCK_CONFLICT' : 'JOURNAL_BUSY');
    }
    let temporary;
    try {
      const exists = fs.existsSync(this.file);
      const document = exists ? this.#read() : newLiveDocument();
      if (!exists && !initialize) fail('JOURNAL_CORRUPT');
      if (exists && initialize) return null;
      const result = change(document);
      document.selfHash = liveDocumentHash(document);
      const serialized = serializeLiveDocument(document);
      temporary = boundedJournalPath(path.join(this.directory, `live-journal-${randomUUID()}.tmp`));
      const descriptor = fs.openSync(temporary, 'wx');
      try {
        fs.writeFileSync(descriptor, serialized);
        fs.fsyncSync(descriptor);
      } finally { fs.closeSync(descriptor); }
      for (let attempt = 1; attempt <= 25; attempt++) {
        try { fs.renameSync(temporary, this.file); temporary = null; break; }
        catch (error) {
          if (!['EPERM', 'EACCES', 'EBUSY'].includes(error?.code) || attempt === 25) fail('JOURNAL_BUSY');
          Atomics.wait(WAIT, 0, 0, 10);
        }
      }
      return structuredClone(result);
    } finally {
      if (temporary && fs.existsSync(temporary)) fs.unlinkSync(temporary);
      lease.release();
    }
  }
}
