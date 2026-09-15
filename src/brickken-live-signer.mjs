// Bounded live signer and Brickken gateway policy. The signing keys and the
// sandbox API key stay inside the process that constructs LiveSigner; callers
// receive only signed bytes for exactly approved steps and the bounded text of
// the fixed Brickken calls. Every decision is derived from the pinned live
// proposal and the owner's hash-bound run approval, never from the request.
// The authorize* functions hold the whole policy without key material so it
// can be tested on its own; LiveSigner only adds the log, the keys and HTTP.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { createHash, randomUUID } from 'node:crypto';
import { canonicalJson, sha256Canonical } from './brickken-intent.mjs';
import {
  BrickkenLivePlanError,
  GRANT_START_TOLERANCE_SECONDS,
  LIVE_STEP_PREREQUISITES,
  LIVE_STEP_ROUTE,
  LIVE_STEP_SIGNER,
  LIVE_WRITE_STEPS,
  checkLiveTransaction,
  grantValidFrom,
  normalizeLiveTransaction,
  validateFacadeBody,
  validateRunApproval
} from './brickken-live-plan.mjs';
import {
  getBrickkenTransactionStatus,
  parseBrickkenSendResponse,
  parseBrickkenStatusResponse,
  postBrickkenRamsPrepare,
  postBrickkenSend
} from './brickken-http.mjs';
import { parseRamsPrepareResponse } from './brickken-prepare.mjs';

const require = createRequire(import.meta.url);
const ethers = require('../vendor/ethers-6.17.0/ethers.umd.min.cjs');

export const SIGNER_ROLES = Object.freeze(['owner', 'agent']);
// Attempt budgets are bounded per time window, not for the life of the
// approval: the log keeps every attempt as an audit record, and a step that
// used its budget becomes available again when the oldest attempt in the
// window ages out. A short network outage therefore never locks a step for good.
export const MAX_PREPARE_ATTEMPTS = 3;
export const MAX_SEND_ATTEMPTS = 3;
export const PREPARE_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
export const SEND_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOG_BYTES = 4 * 1024 * 1024;
const MAX_SIGNED_HEX = 2 + 2 * 65_536;
const LOG_KIND = 'mandate-desk-live-signer-log';

export class LiveSignerError extends Error {
  constructor(code, details = undefined) {
    super(code);
    this.name = 'LiveSignerError';
    this.code = code;
    this.details = details;
  }
}
function fail(code, details) { throw new LiveSignerError(code, details); }
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value));
}
function shape(value, keys, code = 'REQUEST_INVALID') {
  if (!plain(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(code);
}
function sha256Hex(text) { return createHash('sha256').update(text).digest('hex'); }
// Plan validation failures keep their code at the signer boundary.
function planned(work) {
  try { return work(); }
  catch (error) {
    if (error instanceof BrickkenLivePlanError) fail(error.code);
    throw error;
  }
}
function roleStep(role, step) {
  if (!SIGNER_ROLES.includes(role) || !LIVE_WRITE_STEPS.includes(step)) fail('REQUEST_INVALID');
  // The agent role reaches only execute; the owner role never reaches execute.
  if (LIVE_STEP_SIGNER[step] !== role) fail('ROLE_DENIED');
}
function requireActive(approval, nowMs) {
  if (!Number.isSafeInteger(nowMs) || nowMs < Date.parse(approval.createdAt) || nowMs >= Date.parse(approval.notAfter)) {
    fail('APPROVAL_NOT_ACTIVE');
  }
}
function entriesOf(entries, type) { return entries.filter(entry => entry.type === type); }
// Attempts of one step inside the window that ends now. An entry without a
// readable time counts as recent, so an older log can only be stricter.
function recentAttempts(entries, type, step, nowMs, windowMs) {
  return entriesOf(entries, type).filter(entry => entry.step === step &&
    (typeof entry.at !== 'string' || !Number.isFinite(Date.parse(entry.at)) || nowMs - Date.parse(entry.at) < windowMs));
}
function signedSteps(entries) { return new Set(entriesOf(entries, 'signed').map(entry => entry.step)); }
function requirePrerequisites(entries, step) {
  const signed = signedSteps(entries);
  for (const prerequisite of LIVE_STEP_PREREQUISITES[step]) {
    if (!signed.has(prerequisite)) fail('PREREQUISITE_NOT_SIGNED');
  }
}

// ---------------------------------------------------------------------------
// Policy without key material

export function authorizePrepare({ proposal, approval, entries, request, nowMs }) {
  shape(request, ['role', 'step', 'body']);
  roleStep(request.role, request.step);
  if (LIVE_STEP_ROUTE[request.step] !== 'brickken-api') fail('ROUTE_DENIED');
  requireActive(approval, nowMs);
  if (signedSteps(entries).has(request.step)) fail('STEP_ALREADY_SIGNED');
  requirePrerequisites(entries, request.step);
  const body = planned(() => validateFacadeBody(proposal, request.step, request.body, Math.floor(nowMs / 1000)));
  if (recentAttempts(entries, 'prepare-attempt', request.step, nowMs, PREPARE_ATTEMPT_WINDOW_MS).length >= MAX_PREPARE_ATTEMPTS) {
    fail('PREPARE_ATTEMPTS_EXHAUSTED');
  }
  return body;
}

export function authorizeSign({ proposal, approval, entries, request, nowMs }) {
  shape(request, ['role', 'step', 'transaction']);
  roleStep(request.role, request.step);
  requireActive(approval, nowMs);
  const tx = planned(() => checkLiveTransaction(proposal, request.step, request.transaction));
  if (request.step === 'grant' &&
      Math.abs(planned(() => grantValidFrom(tx.data)) - Math.floor(nowMs / 1000)) > GRANT_START_TOLERANCE_SECONDS) {
    fail('GRANT_WINDOW');
  }
  const existing = entriesOf(entries, 'signed').find(entry => entry.step === request.step);
  if (existing) {
    // The identical request returns the recorded bytes; anything else would be a replacement.
    if (canonicalJson(existing.transaction) === canonicalJson(tx)) return { transaction: tx, repeated: existing };
    fail('STEP_ALREADY_SIGNED');
  }
  requirePrerequisites(entries, request.step);
  if (LIVE_STEP_ROUTE[request.step] === 'brickken-api') {
    const prepared = entriesOf(entries, 'prepared').filter(entry => entry.step === request.step).at(-1);
    if (!prepared || canonicalJson(prepared.transaction) !== canonicalJson(tx)) fail('NOT_PREPARED_BY_BRICKKEN');
  }
  const prior = entriesOf(entries, 'signed').filter(entry => entry.transaction.from === tx.from);
  if (prior.some(entry => BigInt(entry.transaction.nonce) >= BigInt(tx.nonce))) fail('NONCE_NOT_INCREASING');
  const cost = BigInt(tx.gasLimit) * BigInt(tx.maxFeePerGas);
  const spent = prior.reduce((sum, entry) => sum + BigInt(entry.transaction.gasLimit) * BigInt(entry.transaction.maxFeePerGas), 0n);
  if (spent + cost > BigInt(approval.budgetWei[request.role])) fail('BUDGET_EXCEEDED');
  return { transaction: tx, repeated: null };
}

export function authorizeSend({ approval, entries, request, nowMs }) {
  shape(request, ['role', 'step', 'txId', 'signedTransaction']);
  roleStep(request.role, request.step);
  if (LIVE_STEP_ROUTE[request.step] !== 'brickken-api') fail('ROUTE_DENIED');
  requireActive(approval, nowMs);
  const signed = entriesOf(entries, 'signed').find(entry => entry.step === request.step);
  if (!signed || signed.signedTransaction !== request.signedTransaction) fail('NOT_SIGNED_BY_THIS_SIGNER');
  const prepared = entriesOf(entries, 'prepared').filter(entry => entry.step === request.step &&
    canonicalJson(entry.transaction) === canonicalJson(signed.transaction)).at(-1);
  if (!prepared || prepared.txId !== request.txId) fail('TX_ID_NOT_PREPARED');
  if (recentAttempts(entries, 'send-attempt', request.step, nowMs, SEND_ATTEMPT_WINDOW_MS).length >= MAX_SEND_ATTEMPTS) {
    fail('SEND_ATTEMPTS_EXHAUSTED');
  }
  return signed;
}

// ---------------------------------------------------------------------------
// Signing with the pinned ethers bundle

// Decodes signed bytes and returns the complete transaction and its Keccak
// hash. It is also the verifier the live journal uses before recording bytes.
// It is a faithful decoder, not a tamper detector: altered bytes can decode to
// another sender and hash, so every caller compares the result with its own
// independently retained expectation, including the sender.
export function decodeSignedLiveTransaction(bytes) {
  if (typeof bytes !== 'string' || bytes.length > MAX_SIGNED_HEX || !/^0x02(?:[0-9a-f]{2})+$/.test(bytes)) fail('SIGNED_BYTES');
  let tx;
  try { tx = ethers.Transaction.from(bytes); } catch { fail('SIGNED_DECODE'); }
  if (tx.type !== 2 || tx.to === null || tx.from === null || tx.signature === null ||
      (tx.accessList?.length ?? 0) !== 0 || tx.serialized.toLowerCase() !== bytes) fail('SIGNED_DECODE');
  const transactionHash = ethers.keccak256(bytes).toLowerCase();
  if (transactionHash !== tx.hash.toLowerCase()) fail('SIGNED_DECODE');
  return Object.freeze({
    transactionHash,
    transaction: Object.freeze({
      chainId: tx.chainId.toString(),
      from: tx.from.toLowerCase(),
      to: tx.to.toLowerCase(),
      value: tx.value.toString(),
      data: tx.data.toLowerCase(),
      nonce: String(tx.nonce),
      type: 2,
      gasLimit: tx.gasLimit.toString(),
      maxPriorityFeePerGas: tx.maxPriorityFeePerGas.toString(),
      maxFeePerGas: tx.maxFeePerGas.toString()
    })
  });
}

export function signLiveTransaction(transactionInput, signingKey) {
  const tx = normalizeLiveTransaction(transactionInput);
  if (BigInt(tx.nonce) > BigInt(Number.MAX_SAFE_INTEGER)) fail('NONCE');
  const unsigned = ethers.Transaction.from({
    type: 2,
    chainId: BigInt(tx.chainId),
    nonce: Number(tx.nonce),
    to: ethers.getAddress(tx.to),
    value: BigInt(tx.value),
    data: tx.data,
    gasLimit: BigInt(tx.gasLimit),
    maxFeePerGas: BigInt(tx.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(tx.maxPriorityFeePerGas),
    accessList: []
  });
  unsigned.signature = signingKey.sign(unsigned.unsignedHash);
  const signedTransaction = unsigned.serialized.toLowerCase();
  return Object.freeze({ signedTransaction, transactionHash: ethers.keccak256(signedTransaction).toLowerCase() });
}

export function signingKeyAddress(signingKey) {
  if (!(signingKey instanceof ethers.SigningKey)) fail('KEY_INVALID');
  return ethers.computeAddress(signingKey.publicKey).toLowerCase();
}

// ---------------------------------------------------------------------------
// Signer process state

function logHash(document) {
  return sha256Canonical({
    schemaVersion: document.schemaVersion, kind: document.kind,
    approvalSha256: document.approvalSha256, entries: document.entries
  });
}

export class LiveSigner {
  #keys;
  #credential;
  #fetchImpl;
  #document;

  constructor({ proposal, approval, approvalSha256, keys, stateDirectory, credential, fetchImpl = globalThis.fetch, now = () => Date.now() }) {
    if (typeof now !== 'function' || typeof fetchImpl !== 'function') fail('CONFIGURATION');
    this.proposal = proposal;
    this.approval = planned(() => validateRunApproval(approval, proposal));
    if (typeof approvalSha256 !== 'string' || approvalSha256 !== this.approval.approvalSha256) fail('APPROVAL_HASH_MISMATCH');
    shape(keys, SIGNER_ROLES, 'KEYS_INVALID');
    if (signingKeyAddress(keys.owner) !== proposal.principal || signingKeyAddress(keys.agent) !== proposal.agent) {
      fail('KEY_ADDRESS_MISMATCH');
    }
    this.#keys = keys;
    this.#credential = credential;
    this.#fetchImpl = fetchImpl;
    this.now = () => {
      const value = now();
      if (!Number.isSafeInteger(value) || value <= 0) fail('TIME');
      return value;
    };
    if (typeof stateDirectory !== 'string') fail('CONFIGURATION');
    fs.mkdirSync(stateDirectory, { recursive: true });
    this.logFile = path.join(stateDirectory, `signer-log-${this.approval.approvalSha256.slice(0, 16)}.json`);
    this.#document = this.#load();
  }

  status() {
    return {
      approvalSha256: this.approval.approvalSha256,
      notAfter: this.approval.notAfter,
      active: this.now() >= Date.parse(this.approval.createdAt) && this.now() < Date.parse(this.approval.notAfter),
      owner: this.proposal.principal,
      agent: this.proposal.agent,
      signed: entriesOf(this.#document.entries, 'signed').map(entry => ({
        step: entry.step, role: entry.role, nonce: entry.transaction.nonce, transactionHash: entry.transactionHash
      }))
    };
  }

  async prepare(request) {
    const body = authorizePrepare({ proposal: this.proposal, approval: this.approval, entries: this.#document.entries, request, nowMs: this.now() });
    // The attempt is recorded before the network call, so a crash still counts it.
    this.#append({ type: 'prepare-attempt', role: request.role, step: request.step, bodySha256: sha256Canonical(body) });
    let text;
    try {
      text = await postBrickkenRamsPrepare({ credential: this.#credential, operation: request.step, body, fetchImpl: this.#fetchImpl });
    } catch (error) {
      const details = { status: error?.status ?? null, apiErrorCode: error?.apiErrorCode ?? null };
      this.#append({ type: 'prepare-failed', role: request.role, step: request.step, code: String(error?.code ?? 'HTTP_FAILED'), ...details });
      fail(String(error?.code ?? 'HTTP_FAILED'), details);
    }
    let parsed;
    try {
      parsed = parseRamsPrepareResponse(text);
      checkLiveTransaction(this.proposal, request.step, parsed.transaction, { nonce: String(body.nonce) });
    } catch (error) {
      this.#append({ type: 'prepare-rejected', role: request.role, step: request.step, code: String(error?.code ?? 'PREPARATION_REJECTED') });
      fail(String(error?.code ?? 'PREPARATION_REJECTED'));
    }
    this.#append({ type: 'prepared', role: request.role, step: request.step, txId: parsed.txId, transaction: parsed.transaction });
    return { responseText: text };
  }

  sign(request) {
    const { transaction, repeated } = authorizeSign({
      proposal: this.proposal, approval: this.approval, entries: this.#document.entries, request, nowMs: this.now()
    });
    if (repeated) return { signedTransaction: repeated.signedTransaction, transactionHash: repeated.transactionHash, repeated: true };
    const signed = signLiveTransaction(transaction, this.#keys[request.role]);
    const decoded = decodeSignedLiveTransaction(signed.signedTransaction);
    if (canonicalJson(decoded.transaction) !== canonicalJson(transaction) || decoded.transactionHash !== signed.transactionHash) {
      fail('SIGNATURE_CHECK');
    }
    // Recorded and flushed before the bytes leave this process.
    this.#append({
      type: 'signed', role: request.role, step: request.step, transaction,
      signedTransaction: signed.signedTransaction, transactionHash: signed.transactionHash
    });
    return { signedTransaction: signed.signedTransaction, transactionHash: signed.transactionHash, repeated: false };
  }

  async send(request) {
    const signed = authorizeSend({ approval: this.approval, entries: this.#document.entries, request, nowMs: this.now() });
    this.#append({ type: 'send-attempt', role: request.role, step: request.step, transactionHash: signed.transactionHash });
    let text;
    try {
      text = await postBrickkenSend({
        credential: this.#credential, txId: request.txId, signedTransaction: signed.signedTransaction, fetchImpl: this.#fetchImpl
      });
    } catch (error) {
      const details = { status: error?.status ?? null, apiErrorCode: error?.apiErrorCode ?? null };
      this.#append({ type: 'send-failed', role: request.role, step: request.step, code: String(error?.code ?? 'HTTP_FAILED'), ...details });
      fail(String(error?.code ?? 'HTTP_FAILED'), details);
    }
    let parsed;
    try { parsed = parseBrickkenSendResponse(text); }
    catch {
      this.#append({ type: 'send-unreadable', role: request.role, step: request.step });
      fail('SEND_RESPONSE_UNREADABLE');
    }
    this.#append({ type: 'send-accepted', role: request.role, step: request.step, relayTransactionHash: parsed.txHash, status: parsed.status });
    return { relayTransactionHash: parsed.txHash, status: parsed.status, transactionHash: signed.transactionHash };
  }

  async transactionStatus(request) {
    shape(request, ['role', 'step']);
    roleStep(request.role, request.step);
    const signed = entriesOf(this.#document.entries, 'signed').find(entry => entry.step === request.step);
    if (!signed || LIVE_STEP_ROUTE[request.step] !== 'brickken-api') fail('NOT_SIGNED_BY_THIS_SIGNER');
    let text;
    try {
      text = await getBrickkenTransactionStatus({ credential: this.#credential, transactionHash: signed.transactionHash, fetchImpl: this.#fetchImpl });
    } catch (error) {
      fail(String(error?.code ?? 'HTTP_FAILED'), { status: error?.status ?? null, apiErrorCode: error?.apiErrorCode ?? null });
    }
    return parseBrickkenStatusResponse(text);
  }

  #load() {
    const stat = fs.lstatSync(this.logFile, { throwIfNoEntry: false });
    if (!stat) {
      const document = { schemaVersion: 1, kind: LOG_KIND, approvalSha256: this.approval.approvalSha256, entries: [], selfHash: '' };
      document.selfHash = logHash(document);
      this.#persist(document);
      return document;
    }
    if (!stat.isFile() || stat.size > MAX_LOG_BYTES) fail('SIGNER_LOG_INVALID');
    let document;
    try { document = JSON.parse(fs.readFileSync(this.logFile, 'utf8')); } catch { fail('SIGNER_LOG_INVALID'); }
    shape(document, ['schemaVersion', 'kind', 'approvalSha256', 'entries', 'selfHash'], 'SIGNER_LOG_INVALID');
    if (document.schemaVersion !== 1 || document.kind !== LOG_KIND || document.approvalSha256 !== this.approval.approvalSha256 ||
        !Array.isArray(document.entries) || document.selfHash !== logHash(document)) fail('SIGNER_LOG_INVALID');
    // Re-verify every recorded signature so an edited log cannot unlock a replacement.
    for (const entry of entriesOf(document.entries, 'signed')) {
      const decoded = decodeSignedLiveTransaction(entry.signedTransaction);
      const expected = planned(() => checkLiveTransaction(this.proposal, entry.step, entry.transaction));
      if (canonicalJson(decoded.transaction) !== canonicalJson(expected) || decoded.transactionHash !== entry.transactionHash) {
        fail('SIGNER_LOG_INVALID');
      }
    }
    return document;
  }

  #append(entry) {
    const next = structuredClone(this.#document);
    next.entries.push({ at: new Date(this.now()).toISOString(), ...entry });
    next.selfHash = logHash(next);
    this.#persist(next);
    this.#document = next;
  }

  #persist(document) {
    const serialized = JSON.stringify(document, null, 2);
    if (Buffer.byteLength(serialized, 'utf8') > MAX_LOG_BYTES) fail('SIGNER_LOG_FULL');
    const temporary = path.join(path.dirname(this.logFile), `signer-log-${randomUUID()}.tmp`);
    const descriptor = fs.openSync(temporary, 'wx');
    try {
      fs.writeFileSync(descriptor, serialized);
      fs.fsyncSync(descriptor);
    } finally { fs.closeSync(descriptor); }
    fs.renameSync(temporary, this.logFile);
    if (sha256Hex(fs.readFileSync(this.logFile)) !== sha256Hex(serialized)) fail('SIGNER_LOG_WRITE');
  }
}
