// Adversarial, independent coverage of the bounded live signer policy in
// src/brickken-live-signer.mjs. This suite never touches a real keystore or
// wallet file: it uses only the two well-known public Hardhat test private
// keys below, and it never spawns tools/live-signer.mjs (that wrapper is
// checked only by static source assertions at the end of this file). No
// network access is used anywhere; the pure policy functions under test take
// no fetch implementation at all.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import {
  authorizePrepare,
  authorizeSign,
  authorizeSend,
  signLiveTransaction,
  decodeSignedLiveTransaction,
  signingKeyAddress,
  LiveSigner,
  LiveSignerError,
  MAX_PREPARE_ATTEMPTS,
  MAX_SEND_ATTEMPTS
} from '../src/brickken-live-signer.mjs';
import {
  loadLiveProposal,
  buildRunApproval,
  expectedCalldata,
  facadeBody,
  stepTarget,
  stepSignerAddress,
  maxStepCostWei,
  LIVE_STEP_SIGNER,
  GRANT_START_TOLERANCE_SECONDS
} from '../src/brickken-live-plan.mjs';
import { encodeTransferFrom } from '../src/brickken-intent.mjs';

const require = createRequire(import.meta.url);
const ethers = require('../vendor/ethers-6.17.0/ethers.umd.min.cjs');

// Public Hardhat test keys, published in Hardhat's own documentation and
// widely known; never a real credential. Their derived addresses are not the
// KNOWN_PRINCIPAL/KNOWN_AGENT constants baked into brickken-intent.mjs, which
// is exactly what section 7 below exercises.
const KEY_A = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const KEY_B = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const KEY_A_SIGNING = new ethers.SigningKey(KEY_A);
const KEY_B_SIGNING = new ethers.SigningKey(KEY_B);
const neverCalledFetch = () => { throw new Error('fetch must not be called in this test'); };

const proposal = loadLiveProposal();
const CREATED_AT = '2026-09-14T00:00:00.000Z';
const NOT_AFTER = '2026-09-15T00:00:00.000Z';
const approval = buildRunApproval(proposal, { createdAt: CREATED_AT, notAfter: NOT_AFTER, preflight: null });
const NOW_MS = Date.parse('2026-09-14T12:00:00.000Z');
const NOW_S = Math.floor(NOW_MS / 1000);

// Asserts both the error class and its code, so a raw BrickkenLivePlanError or
// BrickkenHttpError leaking through unwrapped is caught, not just a code that
// happens to match on the wrong exception type.
function errCode(code) {
  return error => {
    assert.ok(error instanceof LiveSignerError, `expected a LiveSignerError, got ${error?.constructor?.name}`);
    assert.equal(error.code, code);
    return true;
  };
}

function prepare(request, { entries = [], approvalOverride = approval, nowMs = NOW_MS } = {}) {
  return authorizePrepare({ proposal, approval: approvalOverride, entries, request, nowMs });
}
function sign(request, { entries = [], approvalOverride = approval, nowMs = NOW_MS } = {}) {
  return authorizeSign({ proposal, approval: approvalOverride, entries, request, nowMs });
}
function send(request, { entries = [], approvalOverride = approval, nowMs = NOW_MS } = {}) {
  return authorizeSend({ approval: approvalOverride, entries, request, nowMs });
}
function prepareRequest(role, step, body) { return { role, step, body }; }
function signRequest(role, step, transaction) { return { role, step, transaction }; }
function sendRequest(role, step, txId, signedTransaction) { return { role, step, txId, signedTransaction }; }

// A well-formed transaction for one step. Overrides replace fields after the
// exact expected shape is built, so a test only needs to name what it breaks.
function buildTx(step, overrides = {}) {
  const validFrom = overrides.validFrom ?? NOW_S;
  const base = {
    chainId: proposal.chainId,
    from: stepSignerAddress(proposal, step),
    to: stepTarget(proposal, step),
    value: '0',
    data: step === 'grant' ? expectedCalldata(proposal, step, { validFrom }) : expectedCalldata(proposal, step),
    nonce: '0',
    gasLimit: proposal.gasLimitCaps[step],
    type: 2,
    maxPriorityFeePerGas: proposal.fees.maxPriorityFeePerGas,
    maxFeePerGas: proposal.fees.maxFeePerGas
  };
  const { validFrom: droppedValidFrom, ...rest } = overrides;
  return { ...base, ...rest };
}

// A well-formed Brickken facade body for one step, at NOW_S for grant.
// facadeBody itself requires nonce as a decimal string (validateFacadeBody is
// the layer that converts an untrusted request body's numeric nonce field
// into that string), so this helper does the same conversion.
function validBody(step, { nonce = 0, gasLimit = proposal.gasLimitCaps[step], validFrom = NOW_S } = {}) {
  const options = { nonce: String(nonce), gasLimit };
  if (step === 'grant') options.validFrom = validFrom;
  return facadeBody(proposal, step, options);
}

function signedEntry(step, transaction, extra = {}) {
  return {
    type: 'signed',
    role: LIVE_STEP_SIGNER[step],
    step,
    transaction,
    signedTransaction: extra.signedTransaction ?? ('0x' + '11'.repeat(64)),
    transactionHash: extra.transactionHash ?? ('0x' + '22'.repeat(32))
  };
}
function preparedEntry(step, transaction, txId) {
  return { type: 'prepared', role: LIVE_STEP_SIGNER[step], step, txId, transaction };
}
function signedFor(steps) {
  return steps.map(step => signedEntry(step, buildTx(step)));
}

function flipByteAt(hex, byteIndexFromStart) {
  const prefix = hex.slice(0, 2);
  const body = hex.slice(2);
  const pos = byteIndexFromStart * 2;
  const original = parseInt(body.slice(pos, pos + 2), 16);
  const flipped = (original ^ 0x01).toString(16).padStart(2, '0');
  return prefix + body.slice(0, pos) + flipped + body.slice(pos + 2);
}

// ---------------------------------------------------------------------------
// 1. Role separation and request shape

test('the agent role cannot prepare, sign or send any owner step', () => {
  for (const step of ['setAction', 'approve', 'grant', 'revoke', 'approveReset']) {
    assert.throws(() => prepare(prepareRequest('agent', step, {}), {}), errCode('ROLE_DENIED'));
    assert.throws(() => sign(signRequest('agent', step, {}), {}), errCode('ROLE_DENIED'));
    assert.throws(() => send(sendRequest('agent', step, 'x', '0x00'), {}), errCode('ROLE_DENIED'));
  }
});

test('the owner role cannot prepare, sign or send execute', () => {
  assert.throws(() => prepare(prepareRequest('owner', 'execute', {}), {}), errCode('ROLE_DENIED'));
  assert.throws(() => sign(signRequest('owner', 'execute', {}), {}), errCode('ROLE_DENIED'));
  assert.throws(() => send(sendRequest('owner', 'execute', 'x', '0x00'), {}), errCode('ROLE_DENIED'));
});

test('unknown steps and unknown roles are REQUEST_INVALID', () => {
  assert.throws(() => prepare(prepareRequest('owner', 'unknownStep', {}), {}), errCode('REQUEST_INVALID'));
  assert.throws(() => prepare(prepareRequest('admin', 'setAction', {}), {}), errCode('REQUEST_INVALID'));
  assert.throws(() => sign(signRequest('owner', 'unknownStep', {}), {}), errCode('REQUEST_INVALID'));
  assert.throws(() => sign(signRequest('admin', 'setAction', {}), {}), errCode('REQUEST_INVALID'));
  assert.throws(() => send(sendRequest('owner', 'unknownStep', 'x', '0x00'), {}), errCode('REQUEST_INVALID'));
  assert.throws(() => send(sendRequest('admin', 'setAction', 'x', '0x00'), {}), errCode('REQUEST_INVALID'));
});

test('extra request keys are REQUEST_INVALID', () => {
  assert.throws(() => authorizePrepare({
    proposal, approval, entries: [], nowMs: NOW_MS,
    request: { role: 'owner', step: 'setAction', body: {}, extra: 1 }
  }), errCode('REQUEST_INVALID'));
  assert.throws(() => authorizeSign({
    proposal, approval, entries: [], nowMs: NOW_MS,
    request: { role: 'owner', step: 'setAction', transaction: {}, extra: 1 }
  }), errCode('REQUEST_INVALID'));
  assert.throws(() => authorizeSend({
    approval, entries: [], nowMs: NOW_MS,
    request: { role: 'owner', step: 'setAction', txId: 'x', signedTransaction: '0x00', extra: 1 }
  }), errCode('REQUEST_INVALID'));
});

// ---------------------------------------------------------------------------
// 2. Approval window

test('every authorize function requires the approval window to be active', () => {
  const before = Date.parse(CREATED_AT) - 1;
  const atNotAfter = Date.parse(NOT_AFTER);
  const afterNotAfter = Date.parse(NOT_AFTER) + 1000;
  for (const nowMs of [before, atNotAfter, afterNotAfter]) {
    assert.throws(() => prepare(prepareRequest('owner', 'setAction', {}), { nowMs }), errCode('APPROVAL_NOT_ACTIVE'));
    assert.throws(() => sign(signRequest('owner', 'setAction', {}), { nowMs }), errCode('APPROVAL_NOT_ACTIVE'));
    assert.throws(() => send(sendRequest('owner', 'setAction', 'x', '0x00'), { nowMs }), errCode('APPROVAL_NOT_ACTIVE'));
  }
});

// ---------------------------------------------------------------------------
// 3. authorizePrepare

test('authorizePrepare denies preparing a non-Brickken-route step', () => {
  for (const step of ['approve', 'approveReset']) {
    assert.throws(() => prepare(prepareRequest('owner', step, {}), {}), errCode('ROUTE_DENIED'));
  }
});

test('authorizePrepare refuses to re-prepare an already-signed step', () => {
  const entries = signedFor(['setAction']);
  assert.throws(() => prepare(prepareRequest('owner', 'setAction', {}), { entries }), errCode('STEP_ALREADY_SIGNED'));
});

test('authorizePrepare enforces step prerequisites', () => {
  assert.throws(() => prepare(prepareRequest('owner', 'grant', {}), { entries: [] }), errCode('PREREQUISITE_NOT_SIGNED'));
  assert.throws(() => prepare(prepareRequest('agent', 'execute', {}), { entries: [] }), errCode('PREREQUISITE_NOT_SIGNED'));
});

test('authorizePrepare requires the body to equal the plan\'s exact rebuilt body', () => {
  // Extra key beyond the exact rebuilt shape.
  const withExtraKey = { ...validBody('setAction'), extra: true };
  assert.throws(() => prepare(prepareRequest('owner', 'setAction', withExtraKey), {}), errCode('BODY_MISMATCH'));

  // Gas limit above the step's own cap: the plan rejects it before any comparison.
  const overCapGasLimit = { ...validBody('setAction'), gasLimit: (BigInt(proposal.gasLimitCaps.setAction) + 1n).toString() };
  assert.throws(() => prepare(prepareRequest('owner', 'setAction', overCapGasLimit)), errCode('GAS_LIMIT'));

  // A changed recipient inside execute's inner transferFrom calldata.
  const grantSigned = signedFor(['grant']);
  const changedRecipient = { ...validBody('execute'), data: encodeTransferFrom({
    from: proposal.principal, to: proposal.agent, amount: proposal.amounts.execute
  }) };
  assert.throws(() => prepare(prepareRequest('agent', 'execute', changedRecipient), { entries: grantSigned }), errCode('BODY_MISMATCH'));

  // A changed amount inside the same field.
  const changedAmount = { ...validBody('execute'), data: encodeTransferFrom({
    from: proposal.principal, to: proposal.recipient.address, amount: (BigInt(proposal.amounts.execute) + 1n).toString()
  }) };
  assert.throws(() => prepare(prepareRequest('agent', 'execute', changedAmount), { entries: grantSigned }), errCode('BODY_MISMATCH'));
});

test('authorizePrepare rejects a grant validFrom outside the tolerance window', () => {
  const entries = signedFor(['approve']);
  const farValidFrom = NOW_S + GRANT_START_TOLERANCE_SECONDS + 1;
  const body = validBody('grant', { validFrom: farValidFrom });
  assert.throws(() => prepare(prepareRequest('owner', 'grant', body), { entries }), errCode('GRANT_WINDOW'));
});

test('authorizePrepare exhausts after MAX_PREPARE_ATTEMPTS but not one attempt earlier', () => {
  const body = validBody('setAction');
  const attempt = () => ({ type: 'prepare-attempt', role: 'owner', step: 'setAction', bodySha256: 'a'.repeat(64) });
  const fewerAttempts = Array.from({ length: MAX_PREPARE_ATTEMPTS - 1 }, attempt);
  const result = prepare(prepareRequest('owner', 'setAction', body), { entries: fewerAttempts });
  assert.deepStrictEqual(result, body);
  const exhaustingAttempts = Array.from({ length: MAX_PREPARE_ATTEMPTS }, attempt);
  assert.throws(() => prepare(prepareRequest('owner', 'setAction', body), { entries: exhaustingAttempts }), errCode('PREPARE_ATTEMPTS_EXHAUSTED'));
});

// ---------------------------------------------------------------------------
// 4. authorizeSign

test('authorizeSign accepts a correct non-Brickken-route (approve) transaction with no prepared entry required', () => {
  const tx = buildTx('approve');
  const result = sign(signRequest('owner', 'approve', tx), { entries: [] });
  assert.deepStrictEqual(result.transaction, tx);
  assert.equal(result.repeated, null);
});

test('authorizeSign requires a Brickken-route transaction to equal the latest prepared entry for that step', () => {
  const txA = buildTx('setAction', { nonce: '0' });
  const txB = buildTx('setAction', { nonce: '1' });
  // No prepared entry at all.
  assert.throws(() => sign(signRequest('owner', 'setAction', txA), { entries: [] }), errCode('NOT_PREPARED_BY_BRICKKEN'));
  // The transaction matches an older prepared entry, but a newer, different one is now latest.
  const entries = [preparedEntry('setAction', txA, 'tid-old'), preparedEntry('setAction', txB, 'tid-new')];
  assert.throws(() => sign(signRequest('owner', 'setAction', txA), { entries }), errCode('NOT_PREPARED_BY_BRICKKEN'));
  // The latest prepared entry does authorize its matching signature.
  const result = sign(signRequest('owner', 'setAction', txB), { entries });
  assert.equal(result.repeated, null);
});

test('authorizeSign returns the recorded entry for an identical repeat and rejects any change as STEP_ALREADY_SIGNED', () => {
  const txA = buildTx('approve', { nonce: '3' });
  const recorded = signedEntry('approve', txA);
  const entries = [recorded];

  const repeat = sign(signRequest('owner', 'approve', { ...txA }), { entries });
  assert.equal(repeat.repeated, recorded);
  assert.deepStrictEqual(repeat.transaction, txA);

  const changedNonce = { ...txA, nonce: '4' };
  assert.throws(() => sign(signRequest('owner', 'approve', changedNonce), { entries }), errCode('STEP_ALREADY_SIGNED'));

  const changedGasLimit = { ...txA, gasLimit: (BigInt(txA.gasLimit) - 1n).toString() };
  assert.throws(() => sign(signRequest('owner', 'approve', changedGasLimit), { entries }), errCode('STEP_ALREADY_SIGNED'));

  const changedFee = { ...txA, maxFeePerGas: (BigInt(txA.maxFeePerGas) - 1n).toString() };
  assert.throws(() => sign(signRequest('owner', 'approve', changedFee), { entries }), errCode('STEP_ALREADY_SIGNED'));
});

test('authorizeSign requires strictly increasing nonces for the same signer address across steps', () => {
  const priorTx = buildTx('setAction', { nonce: '5' });
  const entries = [signedEntry('setAction', priorTx)];
  for (const nonce of ['5', '4']) {
    const tx = buildTx('approve', { nonce });
    assert.throws(() => sign(signRequest('owner', 'approve', tx), { entries }), errCode('NONCE_NOT_INCREASING'));
  }
  const okTx = buildTx('approve', { nonce: '6' });
  const result = sign(signRequest('owner', 'approve', okTx), { entries });
  assert.equal(result.repeated, null);
});

test('authorizeSign enforces the per-role budget cumulatively using gasLimit times maxFeePerGas', () => {
  const setActionCost = maxStepCostWei(proposal, 'setAction');
  const approveCost = maxStepCostWei(proposal, 'approve');
  const priorTx = buildTx('setAction', { nonce: '0' });
  const entries = [signedEntry('setAction', priorTx)];
  const nextTx = buildTx('approve', { nonce: '1' });

  // The budget equals exactly the prior spend: any further cost exceeds it.
  const tightApproval = { ...approval, budgetWei: { ...approval.budgetWei, owner: setActionCost } };
  assert.throws(() => sign(signRequest('owner', 'approve', nextTx), { entries, approvalOverride: tightApproval }), errCode('BUDGET_EXCEEDED'));

  // The budget equals exactly the sum of both costs: signing succeeds at the boundary.
  const exactBudget = (BigInt(setActionCost) + BigInt(approveCost)).toString();
  const exactApproval = { ...approval, budgetWei: { ...approval.budgetWei, owner: exactBudget } };
  const result = sign(signRequest('owner', 'approve', nextTx), { entries, approvalOverride: exactApproval });
  assert.equal(result.repeated, null);
});

test('authorizeSign rejects wrong chain, calldata, target, native value, signer, and fee or gas limit above the caps', () => {
  const base = buildTx('setAction');
  const feeCap = BigInt(proposal.fees.maxFeePerGas);
  const priorityCap = BigInt(proposal.fees.maxPriorityFeePerGas);
  const gasCap = BigInt(proposal.gasLimitCaps.setAction);
  const cases = [
    [{ chainId: '1' }, 'WRONG_CHAIN'],
    [{ data: expectedCalldata(proposal, 'approve') }, 'CALLDATA_MISMATCH'],
    [{ to: proposal.token.address }, 'WRONG_TARGET'],
    [{ value: '1' }, 'NATIVE_VALUE'],
    [{ from: proposal.agent }, 'WRONG_SIGNER'],
    [{ maxFeePerGas: (feeCap + 1n).toString() }, 'FEE_CEILING'],
    [{ maxPriorityFeePerGas: (priorityCap + 1n).toString() }, 'PRIORITY_FEE_CEILING'],
    [{ gasLimit: (gasCap + 1n).toString() }, 'GAS_LIMIT_CEILING']
  ];
  for (const [patch, code] of cases) {
    const tx = { ...base, ...patch };
    assert.throws(() => sign(signRequest('owner', 'setAction', tx), {}), errCode(code));
  }
});

test('authorizeSign rejects a grant validFrom outside the 300 second tolerance', () => {
  const farValidFrom = NOW_S + GRANT_START_TOLERANCE_SECONDS + 1;
  const tx = buildTx('grant', { validFrom: farValidFrom });
  assert.throws(() => sign(signRequest('owner', 'grant', tx), { entries: [] }), errCode('GRANT_WINDOW'));
});

test('authorizeSign refuses approveReset before approve is signed', () => {
  const tx = buildTx('approveReset');
  assert.throws(() => sign(signRequest('owner', 'approveReset', tx), { entries: [] }), errCode('PREREQUISITE_NOT_SIGNED'));
});

// ---------------------------------------------------------------------------
// 5. authorizeSend

test('authorizeSend only accepts Brickken-route steps', () => {
  for (const step of ['approve', 'approveReset']) {
    assert.throws(() => send(sendRequest('owner', step, 'x', '0x00'), {}), errCode('ROUTE_DENIED'));
  }
});

test('authorizeSend requires the presented bytes to equal the recorded signature for this step', () => {
  const sig = '0x' + '77'.repeat(64);
  assert.throws(() => send(sendRequest('owner', 'setAction', 'tid', sig), { entries: [] }), errCode('NOT_SIGNED_BY_THIS_SIGNER'));
  const entries = [signedEntry('setAction', buildTx('setAction'), { signedTransaction: sig })];
  assert.throws(() => send(sendRequest('owner', 'setAction', 'tid', '0x' + '88'.repeat(64)), { entries }), errCode('NOT_SIGNED_BY_THIS_SIGNER'));
});

test('authorizeSend requires the txId of the preparation matching the signed transaction, not an earlier different one', () => {
  const txA = buildTx('setAction', { nonce: '0' });
  const txB = buildTx('setAction', { nonce: '1' });
  const sigA = '0x' + '99'.repeat(64);
  const entries = [
    signedEntry('setAction', txA, { signedTransaction: sigA }),
    preparedEntry('setAction', txB, 'tid-old-different-preparation'),
    preparedEntry('setAction', txA, 'tid-correct')
  ];
  assert.throws(() => send(sendRequest('owner', 'setAction', 'tid-old-different-preparation', sigA), { entries }), errCode('TX_ID_NOT_PREPARED'));
  const result = send(sendRequest('owner', 'setAction', 'tid-correct', sigA), { entries });
  assert.equal(result, entries[0]);
});

test('authorizeSend exhausts after MAX_SEND_ATTEMPTS but not one attempt earlier', () => {
  const txA = buildTx('setAction');
  const sigA = '0x' + 'aa'.repeat(64);
  const base = [signedEntry('setAction', txA, { signedTransaction: sigA }), preparedEntry('setAction', txA, 'tid')];
  const attempts = count => Array.from({ length: count }, () => ({ type: 'send-attempt', role: 'owner', step: 'setAction' }));

  const okEntries = [...base, ...attempts(MAX_SEND_ATTEMPTS - 1)];
  const result = send(sendRequest('owner', 'setAction', 'tid', sigA), { entries: okEntries });
  assert.equal(result, base[0]);

  const exhaustedEntries = [...base, ...attempts(MAX_SEND_ATTEMPTS)];
  assert.throws(() => send(sendRequest('owner', 'setAction', 'tid', sigA), { entries: exhaustedEntries }), errCode('SEND_ATTEMPTS_EXHAUSTED'));
});

// ---------------------------------------------------------------------------
// 6. signLiveTransaction / decodeSignedLiveTransaction

test('signLiveTransaction and decodeSignedLiveTransaction round-trip: fields match except from, and the hash is keccak256 of the bytes', () => {
  const tx = buildTx('setAction', { nonce: '2' });
  const signed = signLiveTransaction(tx, KEY_A_SIGNING);
  const decoded = decodeSignedLiveTransaction(signed.signedTransaction);
  assert.equal(decoded.transaction.from, signingKeyAddress(KEY_A_SIGNING));
  assert.deepStrictEqual({ ...decoded.transaction, from: null }, { ...tx, from: null });
  assert.equal(decoded.transactionHash, signed.transactionHash);
  assert.equal(decoded.transactionHash, ethers.keccak256(signed.signedTransaction).toLowerCase());
});

test('flipping one byte of the signature decodes to a different sender and hash rather than being rejected', () => {
  const tx = buildTx('setAction', { nonce: '2' });
  const signed = signLiveTransaction(tx, KEY_A_SIGNING);
  const original = decodeSignedLiveTransaction(signed.signedTransaction);
  const totalBytes = (signed.signedTransaction.length - 2) / 2;
  // The last byte of the buffer is the low byte of the signature's s value.
  const flipped = flipByteAt(signed.signedTransaction, totalBytes - 1);
  const decoded = decodeSignedLiveTransaction(flipped);
  assert.notEqual(decoded.transaction.from, original.transaction.from);
  assert.notEqual(decoded.transactionHash, original.transactionHash);
});

test('flipping one byte of the payload decodes to a different target, sender and hash rather than being rejected', () => {
  const tx = buildTx('setAction', { nonce: '2' });
  const signed = signLiveTransaction(tx, KEY_A_SIGNING);
  const original = decodeSignedLiveTransaction(signed.signedTransaction);
  const toHexNo0x = tx.to.slice(2);
  const idx = signed.signedTransaction.indexOf(toHexNo0x);
  assert.ok(idx > 0, 'the target address must appear literally in the serialized bytes');
  // A byte strictly inside the fixed 20-byte 'to' field never changes the RLP length prefix.
  const byteOffset = (idx - 2) / 2 + 3;
  const flipped = flipByteAt(signed.signedTransaction, byteOffset);
  const decoded = decodeSignedLiveTransaction(flipped);
  assert.notEqual(decoded.transaction.to, original.transaction.to);
  assert.notEqual(decoded.transaction.from, original.transaction.from);
  assert.notEqual(decoded.transactionHash, original.transactionHash);
});

test('decodeSignedLiveTransaction rejects a legacy type 0 transaction', () => {
  const tx = buildTx('setAction', { nonce: '2' });
  const legacy = ethers.Transaction.from({
    type: 0, chainId: BigInt(tx.chainId), nonce: Number(tx.nonce), to: ethers.getAddress(tx.to),
    value: BigInt(tx.value), data: tx.data, gasLimit: BigInt(tx.gasLimit), gasPrice: BigInt(tx.maxFeePerGas)
  });
  legacy.signature = KEY_A_SIGNING.sign(legacy.unsignedHash);
  assert.throws(() => decodeSignedLiveTransaction(legacy.serialized.toLowerCase()), errCode('SIGNED_BYTES'));
});

test('decodeSignedLiveTransaction rejects an EIP-2930 access-list (type 1) transaction', () => {
  const tx = buildTx('setAction', { nonce: '2' });
  const typed = ethers.Transaction.from({
    type: 1, chainId: BigInt(tx.chainId), nonce: Number(tx.nonce), to: ethers.getAddress(tx.to),
    value: BigInt(tx.value), data: tx.data, gasLimit: BigInt(tx.gasLimit), gasPrice: BigInt(tx.maxFeePerGas), accessList: []
  });
  typed.signature = KEY_A_SIGNING.sign(typed.unsignedHash);
  assert.throws(() => decodeSignedLiveTransaction(typed.serialized.toLowerCase()), errCode('SIGNED_BYTES'));
});

test('decodeSignedLiveTransaction rejects a type 2 transaction that carries a non-empty access list', () => {
  const tx = buildTx('setAction', { nonce: '2' });
  const withAccessList = ethers.Transaction.from({
    type: 2, chainId: BigInt(tx.chainId), nonce: Number(tx.nonce), to: ethers.getAddress(tx.to),
    value: BigInt(tx.value), data: tx.data, gasLimit: BigInt(tx.gasLimit),
    maxFeePerGas: BigInt(tx.maxFeePerGas), maxPriorityFeePerGas: BigInt(tx.maxPriorityFeePerGas),
    accessList: [{ address: tx.to, storageKeys: ['0x' + '11'.repeat(32)] }]
  });
  withAccessList.signature = KEY_A_SIGNING.sign(withAccessList.unsignedHash);
  assert.throws(() => decodeSignedLiveTransaction(withAccessList.serialized.toLowerCase()), errCode('SIGNED_DECODE'));
});

test('decodeSignedLiveTransaction rejects uppercase hex', () => {
  const tx = buildTx('setAction', { nonce: '2' });
  const signed = signLiveTransaction(tx, KEY_A_SIGNING);
  const uppercased = '0x' + signed.signedTransaction.slice(2).toUpperCase();
  assert.throws(() => decodeSignedLiveTransaction(uppercased), errCode('SIGNED_BYTES'));
});

// ---------------------------------------------------------------------------
// 7. signingKeyAddress and the LiveSigner constructor

test('signingKeyAddress rejects anything that is not an ethers SigningKey', () => {
  for (const bad of [null, undefined, {}, '0xabc', KEY_A]) {
    assert.throws(() => signingKeyAddress(bad), errCode('KEY_INVALID'));
  }
});

test('LiveSigner cannot be constructed with the public test keys, because they do not match the pinned principal and agent', () => {
  assert.throws(() => new LiveSigner({
    proposal, approval, approvalSha256: approval.approvalSha256,
    keys: { owner: KEY_A_SIGNING, agent: KEY_B_SIGNING },
    stateDirectory: 'unused-state-directory',
    credential: 'unused-test-credential',
    fetchImpl: neverCalledFetch,
    now: () => NOW_MS
  }), errCode('KEY_ADDRESS_MISMATCH'));
});

test('LiveSigner rejects a wrong approval hash', () => {
  assert.throws(() => new LiveSigner({
    proposal, approval, approvalSha256: 'f'.repeat(64),
    keys: { owner: KEY_A_SIGNING, agent: KEY_B_SIGNING },
    stateDirectory: 'unused-state-directory',
    credential: 'unused-test-credential',
    fetchImpl: neverCalledFetch,
    now: () => NOW_MS
  }), errCode('APPROVAL_HASH_MISMATCH'));
});

test('LiveSigner rejects an edited approval document', () => {
  const edited = { ...approval, notAfter: '2026-09-16T00:00:00.000Z' };
  assert.throws(() => new LiveSigner({
    proposal, approval: edited, approvalSha256: approval.approvalSha256,
    keys: { owner: KEY_A_SIGNING, agent: KEY_B_SIGNING },
    stateDirectory: 'unused-state-directory',
    credential: 'unused-test-credential',
    fetchImpl: neverCalledFetch,
    now: () => NOW_MS
  }), errCode('APPROVAL_INTEGRITY'));
});

// ---------------------------------------------------------------------------
// 8. Static checks of the loopback HTTP wrapper (never spawned)

test('tools/live-signer.mjs binds 127.0.0.1, its request handler in src/live-signer-http.mjs rejects an Origin header and compares tokens in constant time, and the wrapper never logs the apiKey variable', () => {
  const source = fs.readFileSync(new URL('../tools/live-signer.mjs', import.meta.url), 'utf8');
  // The handler moved to src/live-signer-http.mjs in the third fix round (R2-F05);
  // the wrapper must build its server from that module and nothing else.
  const handler = fs.readFileSync(new URL('../src/live-signer-http.mjs', import.meta.url), 'utf8');
  assert.match(source, /server\.listen\(0, '127\.0\.0\.1'/);
  assert.match(source, /http\.createServer\(createSignerRequestHandler\(/);
  assert.doesNotMatch(source, /req\.headers/);
  assert.match(handler, /req\.headers\.origin !== undefined/);
  assert.match(handler, /import\s*\{[^}]*\btimingSafeEqual\b[^}]*\}\s*from\s*'node:crypto';/);
  assert.match(handler, /timingSafeEqual\(presented, expected\)/);
  const consoleLines = source.split('\n').filter(line => line.includes('console.'));
  assert.ok(consoleLines.length > 0, 'expected the wrapper to print some startup information');
  assert.ok(consoleLines.every(line => !line.includes('apiKey')), 'the apiKey variable must never reach a console call');
});
