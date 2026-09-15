import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  BrickkenJournal, BrickkenJournalError, PROJECT_ROOT, boundedJournalPath
} from '../src/brickken-journal.mjs';
import { verifySetActionPostcheck } from '../src/brickken-postcheck.mjs';

const HASH = '0x' + 'a'.repeat(64);
const OTHER_HASH = '0x' + 'b'.repeat(64);
const BLOCK_HASH = '0x' + 'c'.repeat(64);
const FROM = '0x1111111111111111111111111111111111111111';
const TO = '0x2222222222222222222222222222222222222222';

function directory() {
  const parent = path.join(PROJECT_ROOT, 'test-output');
  fs.mkdirSync(parent, { recursive: true });
  return fs.mkdtempSync(path.join(parent, 'brickken-journal-'));
}
function clock() {
  let second = 0;
  return () => new Date(Date.UTC(2026, 8, 14, 12, 0, second++)).toISOString();
}
function tx(change = {}) {
  const data = '0xa4a22854' + '23b872dd' + '0'.repeat(56) +
    BigInt(1).toString(16).padStart(64, '0') + BigInt(1).toString(16).padStart(64, '0') +
    BigInt(2).toString(16).padStart(64, '0');
  return {
    chainId: '11155111', from: FROM, to: TO, value: '0', data, nonce: '7', type: 2,
    gasLimit: '200000', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000', ...change
  };
}
function pending(change = {}) {
  return {
    operationId: randomUUID(), operationKind: 'setAction', txId: 'fixture-batch-001', preparationHash: 'd'.repeat(64),
    transaction: tx(), createdAt: '2026-09-14T12:00:00.000Z', ...change
  };
}
function postcheckReport() {
  const expectedTransaction = { hash: HASH, ...tx() };
  const expected = {
    transaction: expectedTransaction,
    semantics: { executor: TO, owner: FROM, selector: '0x23b872dd', supported: true, hasAmount: true, amountIndex: 2 }
  };
  const input = {
    schemaVersion: 1, operationKind: 'setAction', expected,
    transaction: { ...expectedTransaction, blockNumber: '100', blockHash: BLOCK_HASH },
    receipt: { transactionHash: HASH, status: 1, from: FROM, to: TO, blockNumber: '100', blockHash: BLOCK_HASH, logs: [] },
    before: { blockNumber: '99', blockHash: OTHER_HASH, state: { action: { supported: false, hasAmount: false, amountIndex: 0 } } },
    after: { blockNumber: '100', blockHash: BLOCK_HASH, state: { action: { supported: true, hasAmount: true, amountIndex: 2 } } },
    observedAt: '2026-09-14T12:00:04.000Z'
  };
  return verifySetActionPostcheck(input, expected);
}
function signed(journal, binding, bytes = '0x010203') {
  return journal.recordSigned(binding.operationId, {
    source: 'injected-fixture', signedTransaction: bytes, signedAt: '2026-09-14T12:00:01.000Z'
  }, value => {
    assert.equal(value, bytes);
    return { transactionHash: HASH, transaction: tx() };
  });
}

test('pending identity is durable, duplicate-bound and txId-unique', () => {
  const dir = directory(), journal = new BrickkenJournal({ directory: dir, now: clock() });
  const binding = pending();
  assert.equal(journal.createPending(binding).state, 'pending');
  assert.deepEqual(journal.createPending(binding), journal.get(binding.operationId));
  assert.throws(() => journal.createPending({ ...binding, preparationHash: 'e'.repeat(64) }), { code: 'OPERATION_ID_CONFLICT' });
  assert.throws(() => journal.createPending({ ...pending(), txId: binding.txId }), { code: 'TX_ID_CONFLICT' });
  assert.equal(new BrickkenJournal({ directory: dir }).get(binding.operationId).transaction.nonce, '7');
});

test('journal size guard preserves the prior readable history', () => {
  const journal = new BrickkenJournal({ directory: directory(), now: clock() });
  const largeData = '0x' + 'ab'.repeat(256 * 1024);
  let stopped = false;
  for (let index = 0; index < 32; index++) {
    const before = fs.readFileSync(journal.file);
    try {
      journal.createPending(pending({
        txId: `fixture-large-${index}`,
        transaction: tx({ data: largeData, nonce: String(index) })
      }));
    } catch (error) {
      assert.equal(error.code, 'JOURNAL_TOO_LARGE');
      assert.deepEqual(fs.readFileSync(journal.file), before);
      stopped = true;
      break;
    }
  }
  assert.equal(stopped, true);
  assert.ok(journal.list().length > 0);
});

test('signed fixture bytes require an independent full decoded transaction match', () => {
  const journal = new BrickkenJournal({ directory: directory(), now: clock() }), binding = pending();
  journal.createPending(binding);
  const record = signed(journal, binding);
  assert.equal(record.state, 'signed');
  assert.equal(record.signed.ethereumTransactionHash, HASH);
  assert.match(record.signed.signedBytesSha256, /^[a-f0-9]{64}$/);
  assert.equal(Object.hasOwn(record.signed, 'transactionHashSha256'), false);
  assert.deepEqual(journal.createPending(binding), record);

  for (const [key, value] of Object.entries({
    chainId: '1', from: TO, to: FROM, value: '1', data: '0x87654321', nonce: '8', type: 0,
    gasLimit: '199999', maxPriorityFeePerGas: '999999999', maxFeePerGas: '1999999999'
  })) {
    const other = new BrickkenJournal({ directory: directory(), now: clock() }), candidate = pending();
    other.createPending(candidate);
    assert.throws(() => other.recordSigned(candidate.operationId, {
      source: 'injected-fixture', signedTransaction: '0x010203', signedAt: '2026-09-14T12:00:01.000Z'
    }, () => ({ transactionHash: HASH, transaction: tx({ [key]: value }) })), key);
  }
  assert.throws(() => journal.recordSigned(binding.operationId, {
    source: 'verified-wallet', signedTransaction: '0x010203', signedAt: '2026-09-14T12:00:02.000Z'
  }, () => ({ transactionHash: HASH, transaction: tx() })), { code: 'SIGNED_VERIFIER_REQUIRED' });
  assert.throws(() => journal.recordSigned(binding.operationId, {
    source: 'injected-fixture', signedTransaction: '0x040506', signedAt: '2026-09-14T12:00:02.000Z'
  }, () => ({ transactionHash: OTHER_HASH, transaction: tx() })), { code: 'UNRESOLVED_SIGNATURE' });
});

test('two pending previews may share a nonce, but restart preserves the first signature reservation', () => {
  const dir = directory(), journal = new BrickkenJournal({ directory: dir, now: clock() });
  const first = pending(), second = pending({ txId: 'fixture-batch-002' });
  journal.createPending(first); journal.createPending(second); signed(journal, first);
  const reopened = new BrickkenJournal({ directory: dir, now: clock() });
  assert.throws(() => signed(reopened, second), { code: 'NONCE_ALREADY_RESERVED' });
  assert.equal(reopened.get(second.operationId).state, 'pending');
});

test('uncertain broadcast allows only identical bytes and resolves by hash without replacement signing', () => {
  const journal = new BrickkenJournal({ directory: directory(), now: clock() }), binding = pending();
  journal.createPending(binding); signed(journal, binding);
  assert.equal(journal.recordBroadcast(binding.operationId, '0x010203', {
    result: 'uncertain', attemptedAt: '2026-09-14T12:00:02.000Z'
  }).state, 'uncertain');
  assert.throws(() => journal.authorizeIdenticalResend(binding.operationId, '0x010204'), { code: 'SIGNED_BYTES_MISMATCH' });
  assert.deepEqual(journal.authorizeIdenticalResend(binding.operationId, '0x010203'), {
    operationId: binding.operationId, transactionHash: HASH, signedTransaction: '0x010203', identicalBytesOnly: true
  });
  assert.equal(journal.recoverUncertain(binding.operationId, {
    observedAt: '2026-09-14T12:00:03.000Z',
    transactionByHash: { transactionHash: HASH, nonce: '7' }, transactionByNonce: null
  }).state, 'broadcast');
  assert.throws(() => journal.recordSigned(binding.operationId, {
    source: 'injected-fixture', signedTransaction: '0x090909', signedAt: '2026-09-14T12:00:04.000Z'
  }, () => ({ transactionHash: OTHER_HASH, transaction: tx() })), { code: 'UNRESOLVED_SIGNATURE' });
});

test('nonce conflict remains stopped even when the expected hash query is empty or contradictory', () => {
  const journal = new BrickkenJournal({ directory: directory(), now: clock() }), binding = pending();
  journal.createPending(binding); signed(journal, binding);
  journal.recordBroadcast(binding.operationId, '0x010203', { result: 'uncertain', attemptedAt: '2026-09-14T12:00:02.000Z' });
  const conflict = journal.recoverUncertain(binding.operationId, {
    observedAt: '2026-09-14T12:00:03.000Z', transactionByHash: null,
    transactionByNonce: { transactionHash: OTHER_HASH, nonce: '7' }
  });
  assert.equal(conflict.state, 'uncertain');
  assert.equal(conflict.broadcast.result, 'nonce-conflict');
  assert.throws(() => journal.authorizeIdenticalResend(binding.operationId, '0x010203'), { code: 'RESEND_BLOCKED' });
  assert.throws(() => journal.confirm(binding.operationId, {
    transactionHash: HASH, blockNumber: '100', blockHash: BLOCK_HASH, confirmations: 2,
    checkedAt: '2026-09-14T12:00:04.000Z'
  }), { code: 'NONCE_CONFLICT' });
});

test('confirmation recheck detects reorg before semantic verification', () => {
  const journal = new BrickkenJournal({ directory: directory(), now: clock() }), binding = pending();
  journal.createPending(binding); signed(journal, binding);
  journal.recordBroadcast(binding.operationId, '0x010203', { result: 'accepted', attemptedAt: '2026-09-14T12:00:02.000Z' });
  journal.confirm(binding.operationId, {
    transactionHash: HASH, blockNumber: '100', blockHash: BLOCK_HASH, confirmations: 3,
    checkedAt: '2026-09-14T12:00:03.000Z'
  });
  const forged = {
    schemaVersion: 1, kind: 'brickken-semantic-postcheck', operationKind: 'execute', transactionHash: HASH,
    blockNumber: '100', blockHash: BLOCK_HASH, verified: true, checks: ['fixture'], scope: {},
    observedAt: '2026-09-14T12:00:04.000Z'
  };
  assert.throws(() => journal.markSemanticallyVerified(binding.operationId, forged), { code: 'POSTCHECK' });
  const verified = journal.markSemanticallyVerified(binding.operationId, postcheckReport());
  assert.equal(verified.state, 'semantically_verified');
  assert.equal(journal.recheckConfirmation(binding.operationId, {
    transactionHash: HASH, blockNumber: '100', blockHash: BLOCK_HASH,
    checkedAt: '2026-09-14T12:00:05.000Z'
  }).state, 'semantically_verified');
  const reorg = journal.recheckConfirmation(binding.operationId, {
    transactionHash: HASH, blockNumber: '100', blockHash: OTHER_HASH,
    checkedAt: '2026-09-14T12:00:06.000Z'
  });
  assert.equal(reorg.state, 'uncertain');
  assert.equal(reorg.confirmation, null);
  assert.equal(reorg.semanticVerification, null);
});

test('a branded semantic report cannot verify another stored operation kind', () => {
  const journal = new BrickkenJournal({ directory: directory(), now: clock() });
  const binding = pending({ operationKind: 'approve' });
  journal.createPending(binding); signed(journal, binding);
  journal.recordBroadcast(binding.operationId, '0x010203', { result: 'accepted', attemptedAt: '2026-09-14T12:00:02.000Z' });
  journal.confirm(binding.operationId, {
    transactionHash: HASH, blockNumber: '100', blockHash: BLOCK_HASH, confirmations: 3,
    checkedAt: '2026-09-14T12:00:03.000Z'
  });
  assert.throws(() => journal.markSemanticallyVerified(binding.operationId, postcheckReport()), { code: 'POSTCHECK_KIND' });
  assert.equal(journal.get(binding.operationId).state, 'confirmed');
});

test('corrupt files, locks, outside paths and linked paths fail closed without deletion', () => {
  const dir = directory(), journal = new BrickkenJournal({ directory: dir, now: clock() });
  const original = fs.readFileSync(journal.file, 'utf8');
  const parsed = JSON.parse(original); parsed.operations.push({});
  fs.writeFileSync(journal.file, JSON.stringify(parsed));
  assert.throws(() => journal.list(), { code: 'JOURNAL_CORRUPT' });
  assert.equal(fs.existsSync(journal.file), true);

  const lockedDir = directory(), locked = new BrickkenJournal({ directory: lockedDir, now: clock() });
  fs.writeFileSync(locked.lock, '{"existing":true}', { flag: 'wx' });
  assert.throws(() => locked.createPending(pending()), { code: 'JOURNAL_BUSY' });
  assert.equal(fs.readFileSync(locked.lock, 'utf8'), '{"existing":true}');
  assert.throws(() => boundedJournalPath(path.resolve(PROJECT_ROOT, '..', 'outside-journal')), { code: 'PATH_SCOPE' });

  const linkRoot = directory(), target = directory(), link = path.join(linkRoot, 'linked');
  try {
    fs.symlinkSync(target, link, 'junction');
    assert.throws(() => new BrickkenJournal({ directory: link }), { code: 'PATH_SCOPE' });
  } catch (error) {
    if (!(error instanceof BrickkenJournalError) && !['EPERM', 'EACCES'].includes(error?.code)) throw error;
  }
});
