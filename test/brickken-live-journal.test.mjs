import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { ROOT } from '../src/store.mjs';
import {
  BrickkenJournal, LiveBrickkenJournal, PROJECT_ROOT, LIVE_SIGNER_SOURCE, livePostcheckKind
} from '../src/brickken-journal.mjs';
import { signLiveTransaction, decodeSignedLiveTransaction } from '../src/brickken-live-signer.mjs';
import { EVENT_TOPICS, verifyApprovePostcheck } from '../src/brickken-postcheck.mjs';

// The public Hardhat test key. Its address is well known and holds no real funds.
const require = createRequire(import.meta.url);
const ethers = require('../vendor/ethers-6.17.0/ethers.umd.min.cjs');
const SIGNING_KEY = new ethers.SigningKey('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
const FROM = ethers.computeAddress(SIGNING_KEY.publicKey).toLowerCase();

const TO = '0x2222222222222222222222222222222222222222';
const TOKEN = '0x5555555555555555555555555555555555555555';
const SPENDER = '0x6666666666666666666666666666666666666666';
const BLOCK_HASH = '0x' + 'c'.repeat(64);
const BEFORE_BLOCK_HASH = '0x' + '3'.repeat(64);

function directory() {
  const parent = path.join(ROOT, 'test-output');
  fs.mkdirSync(parent, { recursive: true });
  return fs.mkdtempSync(path.join(parent, 'live-journal-'));
}
function clock() {
  let second = 0;
  return () => new Date(Date.UTC(2026, 8, 14, 12, 0, second++)).toISOString();
}
function tx(change = {}) {
  return {
    chainId: '11155111', from: FROM, to: TO, value: '0', data: '0x12345678', nonce: '1', type: 2,
    gasLimit: '200000', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000', ...change
  };
}
function wordUintHex(value) { return BigInt(value).toString(16).padStart(64, '0'); }
function wordAddressHex(value) { return '0'.repeat(24) + value.slice(2).toLowerCase(); }
function topicAddress(value) { return '0x' + wordAddressHex(value); }
function approveCalldata(spender, amount) { return '0x095ea7b3' + wordAddressHex(spender) + wordUintHex(amount); }
// approveReset always resets the allowance to zero; the amount is fixed at 0.
function approveResetTx(change = {}) {
  return tx({ to: TOKEN, data: approveCalldata(SPENDER, '0'), ...change });
}
function binding(change = {}) {
  return {
    operationId: randomUUID(), operationKind: 'approve', route: 'sepolia-rpc', apiTxId: null,
    preparationHash: 'd'.repeat(64), transaction: tx(), createdAt: '2026-09-14T12:00:00.000Z', ...change
  };
}
function signedInput(bytes, change = {}) {
  return {
    source: LIVE_SIGNER_SOURCE, approvalSha256: 'f'.repeat(64), signedTransaction: bytes,
    signedAt: '2026-09-14T12:00:01.000Z', ...change
  };
}
function confirmInput(hash, change = {}) {
  return {
    transactionHash: hash, blockNumber: '1000', blockHash: BLOCK_HASH, secondaryBlockHash: BLOCK_HASH,
    receiptStatus: 1, confirmations: 1, checkedAt: '2026-09-14T12:00:05.000Z', ...change
  };
}
// Signs record.transaction with the real key and records it through the real decoder.
function signOperation(journal, record) {
  const good = signLiveTransaction(record.transaction, SIGNING_KEY);
  journal.recordSigned(record.operationId, signedInput(good.signedTransaction), decodeSignedLiveTransaction);
  return good;
}
function broadcastAccepted(journal, record, good, change = {}) {
  return journal.recordBroadcast(record.operationId, good.signedTransaction, {
    result: 'accepted', attemptedAt: '2026-09-14T12:00:02.000Z', relayTransactionHash: good.transactionHash, ...change
  });
}
// A synthetic approve(spender, 0) envelope whose transaction/receipt/block identity is
// derived from `record.transaction` and the supplied confirmationLike, following the
// fixture shape in test/brickken-postcheck.test.mjs, but marked as a live RPC observation.
function approveResetReport(record, confirmationLike, beforeAllowance = '10000') {
  const expectedTransaction = {
    hash: confirmationLike.transactionHash, chainId: record.transaction.chainId, from: record.transaction.from,
    to: record.transaction.to, value: record.transaction.value, data: record.transaction.data,
    nonce: record.transaction.nonce, type: 2, gasLimit: record.transaction.gasLimit,
    maxPriorityFeePerGas: record.transaction.maxPriorityFeePerGas, maxFeePerGas: record.transaction.maxFeePerGas
  };
  const semantics = { token: TOKEN, owner: record.transaction.from, spender: SPENDER, amount: '0' };
  const approvalLog = {
    address: TOKEN, topics: [EVENT_TOPICS.Approval, topicAddress(record.transaction.from), topicAddress(SPENDER)],
    data: '0x' + wordUintHex('0'), transactionHash: confirmationLike.transactionHash,
    blockNumber: confirmationLike.blockNumber, blockHash: confirmationLike.blockHash, logIndex: '0', removed: false
  };
  const input = {
    schemaVersion: 1, operationKind: 'approve', expected: { transaction: expectedTransaction, semantics },
    transaction: { ...expectedTransaction, blockNumber: confirmationLike.blockNumber, blockHash: confirmationLike.blockHash },
    receipt: {
      transactionHash: confirmationLike.transactionHash, status: 1, from: expectedTransaction.from, to: expectedTransaction.to,
      blockNumber: confirmationLike.blockNumber, blockHash: confirmationLike.blockHash, logs: [approvalLog]
    },
    before: {
      blockNumber: String(BigInt(confirmationLike.blockNumber) - 1n), blockHash: BEFORE_BLOCK_HASH,
      state: { allowance: beforeAllowance }
    },
    after: { blockNumber: confirmationLike.blockNumber, blockHash: confirmationLike.blockHash, state: { allowance: '0' } },
    observedAt: '2026-09-14T12:00:10.000Z'
  };
  return verifyApprovePostcheck(input, input.expected, { observationSource: 'sepolia-rpc-block-bound' });
}
// Creates, signs, broadcasts and confirms one approveReset operation end to end.
function confirmedApproveReset(journal, nonce) {
  const record = journal.createPending(binding({
    operationId: randomUUID(), operationKind: 'approveReset', route: 'sepolia-rpc', apiTxId: null,
    transaction: approveResetTx({ nonce })
  }));
  const good = signOperation(journal, record);
  broadcastAccepted(journal, record, good);
  const confirmed = journal.confirm(record.operationId, confirmInput(good.transactionHash));
  return { confirmed, good };
}

test('construction creates a schemaVersion 2 document, rejects a directory outside the project, and detects tampering', () => {
  const dir = directory();
  const journal = new LiveBrickkenJournal({ directory: dir, now: clock() });
  const raw = JSON.parse(fs.readFileSync(journal.file, 'utf8'));
  assert.equal(raw.schemaVersion, 2);
  assert.equal(raw.kind, 'mandate-desk-live-journal');
  assert.deepEqual(raw.operations, []);
  assert.match(raw.selfHash, /^[a-f0-9]{64}$/);

  assert.throws(() => new LiveBrickkenJournal({ directory: path.resolve(PROJECT_ROOT, '..', 'outside-live-journal') }),
    { code: 'PATH_SCOPE' });

  const created = journal.createPending(binding({ transaction: tx({ nonce: '1' }) }));
  const originalText = fs.readFileSync(journal.file, 'utf8');

  // Change one field but leave selfHash stale: the recomputed hash no longer matches.
  const staleHash = JSON.parse(originalText);
  staleHash.operations[0].preparationHash = 'e'.repeat(64);
  fs.writeFileSync(journal.file, JSON.stringify(staleHash));
  assert.throws(() => journal.list(), { code: 'JOURNAL_CORRUPT' });
  assert.equal(fs.existsSync(journal.file), true);

  // Change the same field and also break selfHash itself: still rejected, on the format check.
  const brokenHash = JSON.parse(originalText);
  brokenHash.operations[0].preparationHash = 'e'.repeat(64);
  brokenHash.selfHash = 'z'.repeat(64);
  fs.writeFileSync(journal.file, JSON.stringify(brokenHash));
  assert.throws(() => journal.list(), { code: 'JOURNAL_CORRUPT' });

  fs.writeFileSync(journal.file, originalText);
  assert.equal(journal.get(created.operationId).operationId, created.operationId);
});

test('createPending enforces the route contract, idempotency, operation kind and apiTxId uniqueness', () => {
  const journal = new LiveBrickkenJournal({ directory: directory(), now: clock() });

  assert.throws(() => journal.createPending(binding({ route: 'sepolia-rpc', apiTxId: 'must-be-null' })),
    { code: 'API_TX_ID_ROUTE' });
  assert.throws(() => journal.createPending(binding({ route: 'brickken-api', apiTxId: null })), { code: 'IDENTIFIER' });
  assert.throws(() => journal.createPending(binding({ operationKind: 'not-a-kind' })), { code: 'OPERATION_KIND' });

  const first = binding({ route: 'sepolia-rpc', apiTxId: null });
  const created = journal.createPending(first);
  assert.equal(created.state, 'pending');
  assert.equal(created.apiTxId, null);
  assert.deepEqual(journal.createPending(first), created);

  assert.throws(() => journal.createPending({ ...first, preparationHash: 'e'.repeat(64) }), { code: 'OPERATION_ID_CONFLICT' });

  const apiFirst = binding({ route: 'brickken-api', apiTxId: 'brickken-batch-001', operationId: randomUUID() });
  journal.createPending(apiFirst);
  const apiDuplicateTxId = binding({ route: 'brickken-api', apiTxId: 'brickken-batch-001', operationId: randomUUID() });
  assert.throws(() => journal.createPending(apiDuplicateTxId), { code: 'TX_ID_CONFLICT' });
});

test('replacePending only replaces an unsigned pending record and preserves apiTxId uniqueness', () => {
  const journal = new LiveBrickkenJournal({ directory: directory(), now: clock() });
  const originalBinding = binding({ route: 'sepolia-rpc', apiTxId: null, transaction: tx({ nonce: '3' }) });
  journal.createPending(originalBinding);

  assert.throws(() => journal.replacePending(binding()), { code: 'OPERATION_NOT_FOUND' });

  const kindChange = { ...originalBinding, operationKind: 'grant', transaction: tx({ nonce: '4' }) };
  assert.throws(() => journal.replacePending(kindChange), { code: 'OPERATION_ID_CONFLICT' });

  const replacement = { ...originalBinding, transaction: tx({ nonce: '4' }), preparationHash: 'e'.repeat(64) };
  const replaced = journal.replacePending(replacement);
  assert.equal(replaced.transaction.nonce, '4');
  assert.equal(replaced.preparationHash, 'e'.repeat(64));

  const good = signLiveTransaction(replaced.transaction, SIGNING_KEY);
  journal.recordSigned(replaced.operationId, signedInput(good.signedTransaction), decodeSignedLiveTransaction);
  assert.throws(() => journal.replacePending({ ...replacement, transaction: tx({ nonce: '5' }) }), { code: 'STATE_TRANSITION' });

  const apiA = binding({ route: 'brickken-api', apiTxId: 'batch-a', operationId: randomUUID() });
  const apiB = binding({ route: 'brickken-api', apiTxId: 'batch-b', operationId: randomUUID() });
  journal.createPending(apiA); journal.createPending(apiB);
  assert.throws(() => journal.replacePending({ ...apiB, apiTxId: 'batch-a' }), { code: 'TX_ID_CONFLICT' });
});

test('recordSigned requires the live signer source, approval hash and verifier, and enforces the transition and nonce-reservation rules', () => {
  const journal = new LiveBrickkenJournal({ directory: directory(), now: clock() });
  const record = journal.createPending(binding({ transaction: tx({ nonce: '20' }) }));
  const good = signLiveTransaction(record.transaction, SIGNING_KEY);

  assert.throws(() => journal.recordSigned(record.operationId,
    signedInput(good.signedTransaction, { source: 'injected-fixture' }), decodeSignedLiveTransaction),
  { code: 'SIGNED_VERIFIER_REQUIRED' });
  assert.throws(() => journal.recordSigned(record.operationId, signedInput(good.signedTransaction), null),
    { code: 'SIGNED_VERIFIER_REQUIRED' });
  assert.throws(() => journal.recordSigned(record.operationId,
    signedInput(good.signedTransaction, { approvalSha256: 'not-a-valid-hash' }), decodeSignedLiveTransaction),
  { code: 'HASH' });

  const wrongTxBytes = signLiveTransaction(tx({ nonce: '21' }), SIGNING_KEY).signedTransaction;
  assert.throws(() => journal.recordSigned(record.operationId, signedInput(wrongTxBytes), decodeSignedLiveTransaction),
    { code: 'SIGNED_TRANSACTION_MISMATCH' });

  const signedRecord = journal.recordSigned(record.operationId, signedInput(good.signedTransaction), decodeSignedLiveTransaction);
  assert.equal(signedRecord.state, 'signed');
  assert.equal(signedRecord.signed.source, LIVE_SIGNER_SOURCE);
  assert.equal(signedRecord.signed.ethereumTransactionHash, good.transactionHash);

  // Identical bytes and approval hash again: idempotent, returns the same record.
  assert.deepEqual(journal.recordSigned(record.operationId, signedInput(good.signedTransaction), decodeSignedLiveTransaction), signedRecord);

  // Different bytes for an operation that already carries a signature: UNRESOLVED_SIGNATURE.
  // A mock verifier isolates this state-machine check from ECDSA's deterministic signing.
  const mockVerifier = () => ({ transactionHash: good.transactionHash, transaction: record.transaction });
  assert.throws(() => journal.recordSigned(record.operationId,
    signedInput('0x02aaaa', { approvalSha256: 'a'.repeat(64) }), mockVerifier), { code: 'UNRESOLVED_SIGNATURE' });

  // A second operation sharing chainId/from/nonce with an already-signed operation is blocked.
  const second = journal.createPending(binding({ operationId: randomUUID(), transaction: tx({ nonce: '20', to: TOKEN }) }));
  const secondGood = signLiveTransaction(second.transaction, SIGNING_KEY);
  assert.throws(() => journal.recordSigned(second.operationId, signedInput(secondGood.signedTransaction), decodeSignedLiveTransaction),
    { code: 'NONCE_ALREADY_RESERVED' });
});

test('recordBroadcast tracks a relay hash conflict as uncertain and persists the stored relay hash', () => {
  const journal = new LiveBrickkenJournal({ directory: directory(), now: clock() });
  const record = journal.createPending(binding({ transaction: tx({ nonce: '30' }) }));
  const good = signOperation(journal, record);

  assert.throws(() => journal.recordBroadcast(record.operationId, '0x02bbbb',
    { result: 'accepted', attemptedAt: '2026-09-14T12:00:02.000Z', relayTransactionHash: null }),
  { code: 'SIGNED_BYTES_MISMATCH' });

  const accepted = broadcastAccepted(journal, record, good);
  assert.equal(accepted.state, 'broadcast');
  assert.equal(accepted.broadcast.result, 'accepted');
  assert.equal(accepted.broadcast.relayTransactionHash, good.transactionHash);

  const otherRelay = '0x' + 'b'.repeat(64);
  const conflicted = journal.recordBroadcast(record.operationId, good.signedTransaction, {
    result: 'accepted', attemptedAt: '2026-09-14T12:00:03.000Z', relayTransactionHash: otherRelay
  });
  assert.equal(conflicted.state, 'uncertain');
  assert.equal(conflicted.broadcast.relayTransactionHash, otherRelay);

  const stillUncertain = journal.recordBroadcast(record.operationId, good.signedTransaction, {
    result: 'accepted', attemptedAt: '2026-09-14T12:00:04.000Z', relayTransactionHash: null
  });
  assert.equal(stillUncertain.state, 'uncertain');
  assert.equal(stillUncertain.broadcast.relayTransactionHash, otherRelay);
});

test('recoverUncertain resolves an exact-hash observation to broadcast, detects a nonce conflict, and still recovers after one', () => {
  const journal = new LiveBrickkenJournal({ directory: directory(), now: clock() });
  const record = journal.createPending(binding({ transaction: tx({ nonce: '40' }) }));
  const good = signOperation(journal, record);
  journal.recordBroadcast(record.operationId, good.signedTransaction, {
    result: 'uncertain', attemptedAt: '2026-09-14T12:00:02.000Z', relayTransactionHash: null
  });

  assert.throws(() => journal.recoverUncertain(record.operationId, {
    observedAt: '2026-09-14T12:00:03.000Z',
    transactionByHash: { transactionHash: '0x' + 'e'.repeat(64), nonce: '40', from: FROM },
    latestNonce: '40'
  }), { code: 'RECOVERY_MISMATCH' });

  assert.throws(() => journal.recoverUncertain(record.operationId, {
    observedAt: '2026-09-14T12:00:03.000Z',
    transactionByHash: { transactionHash: good.transactionHash, nonce: '41', from: FROM },
    latestNonce: '40'
  }), { code: 'RECOVERY_MISMATCH' });

  const recovered = journal.recoverUncertain(record.operationId, {
    observedAt: '2026-09-14T12:00:04.000Z',
    transactionByHash: { transactionHash: good.transactionHash, nonce: '40', from: FROM },
    latestNonce: '40'
  });
  assert.equal(recovered.state, 'broadcast');
  assert.equal(recovered.broadcast.result, 'recovered-by-hash');

  const second = journal.createPending(binding({ operationId: randomUUID(), transaction: tx({ nonce: '41', to: TOKEN }) }));
  const secondGood = signOperation(journal, second);
  journal.recordBroadcast(second.operationId, secondGood.signedTransaction, {
    result: 'uncertain', attemptedAt: '2026-09-14T12:00:02.000Z', relayTransactionHash: null
  });

  const conflicted = journal.recoverUncertain(second.operationId, {
    observedAt: '2026-09-14T12:00:05.000Z', transactionByHash: null, latestNonce: '42'
  });
  assert.equal(conflicted.state, 'uncertain');
  assert.equal(conflicted.broadcast.result, 'nonce-conflict');

  assert.throws(() => journal.recordBroadcast(second.operationId, secondGood.signedTransaction, {
    result: 'accepted', attemptedAt: '2026-09-14T12:00:06.000Z', relayTransactionHash: null
  }), { code: 'NONCE_CONFLICT' });
  assert.throws(() => journal.authorizeIdenticalResend(second.operationId, secondGood.signedTransaction), { code: 'RESEND_BLOCKED' });

  const recoveredAfterConflict = journal.recoverUncertain(second.operationId, {
    observedAt: '2026-09-14T12:00:07.000Z',
    transactionByHash: { transactionHash: secondGood.transactionHash, nonce: '41', from: FROM },
    latestNonce: '42'
  });
  assert.equal(recoveredAfterConflict.state, 'broadcast');
  assert.equal(recoveredAfterConflict.broadcast.result, 'recovered-by-hash');
});

test('confirm requires source agreement, sets confirmed or reverted by receipt status, and accepts a repeat with a higher count', () => {
  const journal = new LiveBrickkenJournal({ directory: directory(), now: clock() });
  const record = journal.createPending(binding({ transaction: tx({ nonce: '50' }) }));
  const good = signOperation(journal, record);
  broadcastAccepted(journal, record, good);

  assert.throws(() => journal.confirm(record.operationId,
    confirmInput(good.transactionHash, { secondaryBlockHash: '0x' + 'd'.repeat(64) })),
  { code: 'SOURCE_DISAGREEMENT' });

  const confirmed = journal.confirm(record.operationId, confirmInput(good.transactionHash, { confirmations: 3 }));
  assert.equal(confirmed.state, 'confirmed');
  assert.equal(confirmed.confirmation.confirmations, 3);

  // A repeat confirmation with the same identity but a higher count is accepted.
  const repeated = journal.confirm(record.operationId,
    confirmInput(good.transactionHash, { confirmations: 5, checkedAt: '2026-09-14T12:00:06.000Z' }));
  assert.equal(repeated.state, 'confirmed');
  assert.equal(repeated.confirmation.confirmations, 5);

  // A conflicting second confirmation (different block number, same hash) is rejected.
  assert.throws(() => journal.confirm(record.operationId, confirmInput(good.transactionHash, { blockNumber: '1001' })),
    { code: 'CONFIRMATION_CONFLICT' });

  const second = journal.createPending(binding({ operationId: randomUUID(), transaction: tx({ nonce: '51', to: TOKEN }) }));
  const secondGood = signOperation(journal, second);
  broadcastAccepted(journal, second, secondGood);
  const reverted = journal.confirm(second.operationId, confirmInput(secondGood.transactionHash, { receiptStatus: 0 }));
  assert.equal(reverted.state, 'reverted');
});

test('recheckConfirmation raises the confirmation count on a match and withdraws confirmation and semantic verification on either source mismatch', () => {
  const journal = new LiveBrickkenJournal({ directory: directory(), now: clock() });
  const { confirmed, good } = confirmedApproveReset(journal, '70');
  const confirmation = {
    transactionHash: confirmed.confirmation.transactionHash, blockNumber: confirmed.confirmation.blockNumber,
    blockHash: confirmed.confirmation.blockHash
  };
  const verified = journal.markSemanticallyVerified(confirmed.operationId, approveResetReport(confirmed, confirmation));
  assert.equal(verified.state, 'semantically_verified');

  const rechecked = journal.recheckConfirmation(confirmed.operationId, {
    transactionHash: good.transactionHash, blockNumber: confirmation.blockNumber, blockHash: confirmation.blockHash,
    secondaryBlockHash: confirmation.blockHash, confirmations: 9, checkedAt: '2026-09-14T12:00:11.000Z'
  });
  assert.equal(rechecked.state, 'semantically_verified');
  assert.equal(rechecked.confirmation.confirmations, 9);
  assert.notEqual(rechecked.semanticVerification, null);

  const reorged = journal.recheckConfirmation(confirmed.operationId, {
    transactionHash: good.transactionHash, blockNumber: confirmation.blockNumber, blockHash: '0x' + 'f'.repeat(64),
    secondaryBlockHash: '0x' + 'f'.repeat(64), confirmations: 10, checkedAt: '2026-09-14T12:00:12.000Z'
  });
  assert.equal(reorged.state, 'uncertain');
  assert.equal(reorged.confirmation, null);
  assert.equal(reorged.semanticVerification, null);

  // A secondary-only mismatch (primary block hash still agrees) also withdraws confirmation.
  const { confirmed: confirmed2 } = confirmedApproveReset(journal, '71');
  const secondaryMismatch = journal.recheckConfirmation(confirmed2.operationId, {
    transactionHash: confirmed2.confirmation.transactionHash, blockNumber: confirmed2.confirmation.blockNumber,
    blockHash: confirmed2.confirmation.blockHash, secondaryBlockHash: '0x' + 'a'.repeat(64),
    confirmations: 2, checkedAt: '2026-09-14T12:00:13.000Z'
  });
  assert.equal(secondaryMismatch.state, 'uncertain');
  assert.equal(secondaryMismatch.confirmation, null);
});

test('markSemanticallyVerified accepts only a genuine, identity-matched postcheck report, mapping approveReset through livePostcheckKind', () => {
  const journal = new LiveBrickkenJournal({ directory: directory(), now: clock() });

  // Requires confirmed: an operation that is merely broadcast is refused.
  const stillBroadcast = journal.createPending(binding({
    operationId: randomUUID(), operationKind: 'approveReset', transaction: approveResetTx({ nonce: '60' })
  }));
  const stillBroadcastGood = signOperation(journal, stillBroadcast);
  broadcastAccepted(journal, stillBroadcast, stillBroadcastGood);
  const dummyReport = approveResetReport(stillBroadcast,
    { transactionHash: stillBroadcastGood.transactionHash, blockNumber: '1000', blockHash: BLOCK_HASH });
  assert.throws(() => journal.markSemanticallyVerified(stillBroadcast.operationId, dummyReport), { code: 'CONFIRMATION_REQUIRED' });

  const { confirmed, good } = confirmedApproveReset(journal, '61');
  const confirmation = {
    transactionHash: confirmed.confirmation.transactionHash, blockNumber: confirmed.confirmation.blockNumber,
    blockHash: confirmed.confirmation.blockHash
  };
  const report = approveResetReport(confirmed, confirmation);
  assert.equal(report.scope.blockBoundRpcObservation, true);
  assert.equal(report.scope.normalizedFixtureInputOnly, false);

  // A plain object copy of a verified report loses its WeakSet branding.
  assert.throws(() => journal.markSemanticallyVerified(confirmed.operationId, { ...report }), { code: 'POSTCHECK' });

  // Identity mismatch: the same transaction hash, but reported in a different block.
  const otherConfirmation = { transactionHash: good.transactionHash, blockNumber: '2000', blockHash: '0x' + 'e'.repeat(64) };
  const mismatchedReport = approveResetReport(confirmed, otherConfirmation);
  assert.throws(() => journal.markSemanticallyVerified(confirmed.operationId, mismatchedReport), { code: 'POSTCHECK_IDENTITY' });

  // Wrong kind: a confirmed setAction operation does not alias to 'approve'.
  const setActionRecord = journal.createPending(binding({
    operationId: randomUUID(), operationKind: 'setAction', transaction: tx({ nonce: '62', to: TOKEN })
  }));
  const setActionGood = signOperation(journal, setActionRecord);
  broadcastAccepted(journal, setActionRecord, setActionGood);
  const setActionConfirmed = journal.confirm(setActionRecord.operationId, confirmInput(setActionGood.transactionHash));
  assert.throws(() => journal.markSemanticallyVerified(setActionConfirmed.operationId, report), { code: 'POSTCHECK_KIND' });

  // The real, identity-matched report verifies the approveReset operation through livePostcheckKind.
  assert.equal(livePostcheckKind('approveReset'), 'approve');
  const verified = journal.markSemanticallyVerified(confirmed.operationId, report);
  assert.equal(verified.state, 'semantically_verified');
  assert.equal(verified.semanticVerification.postcheckKind, 'approve');
});

test('the offline BrickkenJournal still rejects live signer bytes as a source', () => {
  const journal = new BrickkenJournal({ directory: directory(), now: clock() });
  const offlineBinding = {
    operationId: randomUUID(), operationKind: 'setAction', txId: 'fixture-live-guard', preparationHash: 'd'.repeat(64),
    transaction: tx(), createdAt: '2026-09-14T12:00:00.000Z'
  };
  journal.createPending(offlineBinding);
  const good = signLiveTransaction(tx(), SIGNING_KEY);
  assert.throws(() => journal.recordSigned(offlineBinding.operationId, {
    source: LIVE_SIGNER_SOURCE, signedTransaction: good.signedTransaction, signedAt: '2026-09-14T12:00:01.000Z'
  }, decodeSignedLiveTransaction), { code: 'SIGNED_VERIFIER_REQUIRED' });
});

test('a restart reads back every recorded state unchanged', () => {
  const dir = directory();
  const journal = new LiveBrickkenJournal({ directory: dir, now: clock() });
  const record = journal.createPending(binding({ transaction: tx({ nonce: '90' }) }));
  const good = signOperation(journal, record);
  broadcastAccepted(journal, record, good);
  const confirmed = journal.confirm(record.operationId, confirmInput(good.transactionHash));
  const before = journal.list();

  const reopened = new LiveBrickkenJournal({ directory: dir, now: clock() });
  assert.deepEqual(reopened.list(), before);
  assert.deepEqual(reopened.get(record.operationId), confirmed);
});
