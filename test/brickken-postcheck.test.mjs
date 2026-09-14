import test from 'node:test';
import assert from 'node:assert/strict';
import {
  EVENT_TOPICS, verifySetActionPostcheck, verifyApprovePostcheck,
  verifyGrantPostcheck, verifyExecutePostcheck, verifyRevokePostcheck
} from '../src/brickken-postcheck.mjs';

const TX_HASH = '0x' + '1'.repeat(64);
const BLOCK_HASH = '0x' + '2'.repeat(64);
const BEFORE_HASH = '0x' + '3'.repeat(64);
const WRONG_HASH = '0x' + '4'.repeat(64);
const PRINCIPAL = '0x1111111111111111111111111111111111111111';
const AGENT = '0x2222222222222222222222222222222222222222';
const EXECUTOR = '0x3333333333333333333333333333333333333333';
const REGISTRY = '0x4444444444444444444444444444444444444444';
const TOKEN = '0x5555555555555555555555555555555555555555';
const RECIPIENT = '0x6666666666666666666666666666666666666666';
const PROVIDER = '0x7777777777777777777777777777777777777777';
const ACTION = '0x' + '8'.repeat(64);
const IDENTITY = '0x' + '9'.repeat(64);
const METADATA = '0x' + 'a'.repeat(64);

function wordUint(value) { return BigInt(value).toString(16).padStart(64, '0'); }
function wordAddress(value) { return '0'.repeat(24) + value.slice(2).toLowerCase(); }
function topicAddress(value) { return '0x' + wordAddress(value); }
function setActionData() {
  return '0xa4a22854' + '0'.repeat(56) + '23b872dd' + wordUint(1) + wordUint(1) + wordUint(2);
}
function approveData() { return '0x095ea7b3' + wordAddress(EXECUTOR) + wordUint(10000); }
function grantData() {
  return '0xc6a4ad00' + wordUint(64) + wordUint(512) + wordAddress(AGENT) + wordUint(1800000000) +
    wordUint(1800001800) + wordAddress(PRINCIPAL) + wordAddress(PROVIDER) + IDENTITY.slice(2) +
    wordAddress(TOKEN) + wordUint(10000) + wordUint(10000) + METADATA.slice(2) + wordUint(384) +
    wordUint(0) + wordUint(1) + ACTION.slice(2) + wordUint(0);
}
function executeData() {
  const inner = '23b872dd' + wordAddress(PRINCIPAL) + wordAddress(RECIPIENT) + wordUint(10000);
  return '0x1cff79cd' + wordAddress(TOKEN) + wordUint(64) + wordUint(100) + inner + '0'.repeat(56);
}
function revokeData() {
  return '0x5e20639e' + wordAddress(AGENT) + wordAddress(PRINCIPAL) + wordUint(0) + wordUint(128) + wordUint(0);
}
function log(address, topic, topics, data, logIndex) {
  return {
    address, topics: [topic, ...topics], data, transactionHash: TX_HASH,
    blockNumber: '100', blockHash: BLOCK_HASH, logIndex: String(logIndex), removed: false
  };
}
function expectedTransaction(change = {}) {
  return {
    hash: TX_HASH, chainId: '11155111', from: PRINCIPAL, to: EXECUTOR, value: '0', data: '0x12345678',
    nonce: '7', type: 2, gasLimit: '200000', maxPriorityFeePerGas: '1000000000',
    maxFeePerGas: '2000000000', ...change
  };
}
function envelope(operationKind, semantics, beforeState, afterState, logs = [], change = {}) {
  const expected = expectedTransaction(change.expectedTransaction);
  return {
    schemaVersion: 1, operationKind,
    expected: { transaction: expected, semantics },
    transaction: { ...expected, blockNumber: '100', blockHash: BLOCK_HASH, ...change.transaction },
    receipt: {
      transactionHash: TX_HASH, status: 1, from: expected.from, to: expected.to,
      blockNumber: '100', blockHash: BLOCK_HASH, logs, ...change.receipt
    },
    before: { blockNumber: '99', blockHash: BEFORE_HASH, state: beforeState, ...change.before },
    after: { blockNumber: '100', blockHash: BLOCK_HASH, state: afterState, ...change.after },
    observedAt: '2026-09-14T12:00:00.000Z'
  };
}
function mandate(change = {}) {
  return {
    agent: AGENT, validFrom: '1800000000', validUntil: '1800001800', principal: PRINCIPAL,
    revoked: false, complianceProvider: PROVIDER, identityRef: IDENTITY, asset: TOKEN,
    maxTransactionValue: '10000', maxCumulativeValue: '10000', cumulativeUsed: '0', metadata: METADATA,
    ...change
  };
}
function approveInput() {
  const approval = log(TOKEN, EVENT_TOPICS.Approval,
    [topicAddress(PRINCIPAL), topicAddress(EXECUTOR)], '0x' + wordUint(10000), 0);
  return envelope('approve', { token: TOKEN, owner: PRINCIPAL, spender: EXECUTOR, amount: '10000' },
    { allowance: '0' }, { allowance: '10000' }, [approval], { expectedTransaction: { to: TOKEN, data: approveData() } });
}
function grantInput() {
  const granted = log(REGISTRY, EVENT_TOPICS.MandateGranted,
    [topicAddress(AGENT), topicAddress(PRINCIPAL)],
    '0x' + wordAddress(PROVIDER) + wordAddress(TOKEN) + wordUint(1800000000) + wordUint(1800001800) + METADATA.slice(2), 0);
  const enabled = log(REGISTRY, EVENT_TOPICS.ActionEnabled,
    [topicAddress(AGENT), topicAddress(PRINCIPAL), ACTION], '0x', 1);
  const semantics = {
    registry: REGISTRY, agent: AGENT, principal: PRINCIPAL, complianceProvider: PROVIDER, asset: TOKEN,
    validFrom: '1800000000', validUntil: '1800001800', identityRef: IDENTITY, metadata: METADATA, action: ACTION,
    maxTransactionValue: '10000', maxCumulativeValue: '10000'
  };
  return envelope('grant', semantics, { mandate: null, actionEnabled: false },
    { mandate: mandate(), actionEnabled: true }, [granted, enabled], { expectedTransaction: { to: REGISTRY, data: grantData() } });
}
function executeInput() {
  const transfer = log(TOKEN, EVENT_TOPICS.Transfer,
    [topicAddress(PRINCIPAL), topicAddress(RECIPIENT)], '0x' + wordUint(10000), 0);
  const execution = log(REGISTRY, EVENT_TOPICS.ExecutionRecorded,
    [topicAddress(AGENT), topicAddress(PRINCIPAL), ACTION], '0x' + wordUint(10000) + wordUint(10000), 1);
  const semantics = {
    registry: REGISTRY, executor: EXECUTOR, token: TOKEN, agent: AGENT, principal: PRINCIPAL, recipient: RECIPIENT,
    action: ACTION, amount: '10000', maxTransactionValue: '10000', maxCumulativeValue: '10000', canExecuteAfter: false
  };
  return envelope('execute', semantics, {
    principalBalance: '20000', recipientBalance: '500', allowance: '10000', mandate: mandate(), canExecute: true
  }, {
    principalBalance: '10000', recipientBalance: '10500', allowance: '0',
    mandate: mandate({ cumulativeUsed: '10000' }), canExecute: false
  }, [transfer, execution], { expectedTransaction: { from: AGENT, data: executeData() } });
}

test('setAction requires exact transaction/receipt identity and the source-defined action state transition', () => {
  const input = envelope('setAction', {
    executor: EXECUTOR, owner: PRINCIPAL, selector: '0x23b872dd', supported: true, hasAmount: true, amountIndex: 2
  }, { action: { supported: false, hasAmount: false, amountIndex: 0 } },
  { action: { supported: true, hasAmount: true, amountIndex: 2 } }, [], { expectedTransaction: { data: setActionData() } });
  const report = verifySetActionPostcheck(input, input.expected);
  assert.equal(report.operationKind, 'setAction');
  assert.equal(report.scope.abiSourceMatched, true);
  assert.equal(report.scope.rpcAuthenticityVerified, false);
  assert.equal(Object.isFrozen(report), true);
  assert.throws(() => verifySetActionPostcheck({ ...input, transaction: { ...input.transaction, nonce: '8' } }, input.expected), {
    code: 'TRANSACTION_IDENTITY'
  });
});

test('approve requires the exact Approval event and resulting allowance', () => {
  const approval = log(TOKEN, EVENT_TOPICS.Approval,
    [topicAddress(PRINCIPAL), topicAddress(EXECUTOR)], '0x' + wordUint(10000), 0);
  const input = envelope('approve', { token: TOKEN, owner: PRINCIPAL, spender: EXECUTOR, amount: '10000' },
    { allowance: '0' }, { allowance: '10000' }, [approval], { expectedTransaction: { to: TOKEN, data: approveData() } });
  assert.equal(verifyApprovePostcheck(input, input.expected).verified, true);
  assert.throws(() => verifyApprovePostcheck({ ...input, after: { ...input.after, state: { allowance: '9999' } } }, input.expected), {
    code: 'ALLOWANCE_MISMATCH'
  });
  const wrongEvent = structuredClone(input); wrongEvent.receipt.logs[0].topics[2] = topicAddress(RECIPIENT);
  assert.throws(() => verifyApprovePostcheck(wrongEvent, input.expected), { code: 'APPROVAL_EVENT_MISMATCH' });
});

test('grant requires matched MandateGranted and ActionEnabled events plus complete mandate state', () => {
  const granted = log(REGISTRY, EVENT_TOPICS.MandateGranted,
    [topicAddress(AGENT), topicAddress(PRINCIPAL)],
    '0x' + wordAddress(PROVIDER) + wordAddress(TOKEN) + wordUint(1800000000) + wordUint(1800001800) + METADATA.slice(2), 0);
  const enabled = log(REGISTRY, EVENT_TOPICS.ActionEnabled,
    [topicAddress(AGENT), topicAddress(PRINCIPAL), ACTION], '0x', 1);
  const semantics = {
    registry: REGISTRY, agent: AGENT, principal: PRINCIPAL, complianceProvider: PROVIDER, asset: TOKEN,
    validFrom: '1800000000', validUntil: '1800001800', identityRef: IDENTITY, metadata: METADATA, action: ACTION,
    maxTransactionValue: '10000', maxCumulativeValue: '10000'
  };
  const input = envelope('grant', semantics, { mandate: null, actionEnabled: false },
    { mandate: mandate(), actionEnabled: true }, [granted, enabled], { expectedTransaction: { to: REGISTRY, data: grantData() } });
  assert.equal(verifyGrantPostcheck(input, input.expected).verified, true);

  const missingAction = structuredClone(input); missingAction.receipt.logs.pop();
  assert.throws(() => verifyGrantPostcheck(missingAction, input.expected), { code: 'EVENT_COUNT' });
  const stale = structuredClone(input); stale.before.state = { mandate: mandate({ revoked: true }), actionEnabled: true };
  assert.throws(() => verifyGrantPostcheck(stale, input.expected), { code: 'STALE_GRANT_STATE' });
});

test('execute verifies both source-matched events and every balance, allowance and cumulative delta', () => {
  const transfer = log(TOKEN, EVENT_TOPICS.Transfer,
    [topicAddress(PRINCIPAL), topicAddress(RECIPIENT)], '0x' + wordUint(10000), 0);
  const execution = log(REGISTRY, EVENT_TOPICS.ExecutionRecorded,
    [topicAddress(AGENT), topicAddress(PRINCIPAL), ACTION], '0x' + wordUint(10000) + wordUint(10000), 1);
  const semantics = {
    registry: REGISTRY, executor: EXECUTOR, token: TOKEN, agent: AGENT, principal: PRINCIPAL, recipient: RECIPIENT,
    action: ACTION, amount: '10000', maxTransactionValue: '10000', maxCumulativeValue: '10000', canExecuteAfter: false
  };
  const before = {
    principalBalance: '20000', recipientBalance: '500', allowance: '10000', mandate: mandate(), canExecute: true
  };
  const after = {
    principalBalance: '10000', recipientBalance: '10500', allowance: '0',
    mandate: mandate({ cumulativeUsed: '10000' }), canExecute: false
  };
  const input = envelope('execute', semantics, before, after, [transfer, execution], {
    expectedTransaction: { from: AGENT, data: executeData() }
  });
  assert.equal(verifyExecutePostcheck(input, input.expected).verified, true);

  for (const [field, value] of Object.entries({
    principalBalance: '10001', recipientBalance: '10499', allowance: '1'
  })) {
    const stale = structuredClone(input); stale.after.state[field] = value;
    assert.throws(() => verifyExecutePostcheck(stale, input.expected), { code: 'TOKEN_DELTA_MISMATCH' });
  }
  const cumulative = structuredClone(input); cumulative.after.state.mandate.cumulativeUsed = '9999';
  assert.throws(() => verifyExecutePostcheck(cumulative, input.expected), { code: 'CUMULATIVE_DELTA_MISMATCH' });
  const replayed = structuredClone(input); replayed.receipt.logs.push(structuredClone(replayed.receipt.logs[0])); replayed.receipt.logs[2].logIndex = '2';
  assert.throws(() => verifyExecutePostcheck(replayed, input.expected), { code: 'EVENT_COUNT' });
});

test('revoke proves the event and state transition while preserving action storage', () => {
  const revoked = log(REGISTRY, EVENT_TOPICS.MandateRevoked,
    [topicAddress(AGENT), topicAddress(PRINCIPAL)], '0x' + wordAddress(PRINCIPAL), 0);
  const input = envelope('revoke', { registry: REGISTRY, agent: AGENT, principal: PRINCIPAL, revokedBy: PRINCIPAL },
    { mandate: mandate(), actionEnabled: true, canExecute: true },
    { mandate: mandate({ revoked: true }), actionEnabled: true, canExecute: false }, [revoked],
    { expectedTransaction: { to: REGISTRY, data: revokeData() } });
  assert.equal(verifyRevokePostcheck(input, input.expected).verified, true);
  const stillExecutable = structuredClone(input); stillExecutable.after.state.canExecute = true;
  assert.throws(() => verifyRevokePostcheck(stillExecutable, input.expected), { code: 'REVOCATION_EFFECT_MISMATCH' });
  const clearedAction = structuredClone(input); clearedAction.after.state.actionEnabled = false;
  assert.throws(() => verifyRevokePostcheck(clearedAction, input.expected), { code: 'REVOCATION_EFFECT_MISMATCH' });
});

test('status-only, mismatched receipt/log identity, removed logs and reorged snapshots fail closed', () => {
  const approval = log(TOKEN, EVENT_TOPICS.Approval,
    [topicAddress(PRINCIPAL), topicAddress(EXECUTOR)], '0x' + wordUint(10000), 0);
  const input = envelope('approve', { token: TOKEN, owner: PRINCIPAL, spender: EXECUTOR, amount: '10000' },
    { allowance: '0' }, { allowance: '10000' }, [approval], { expectedTransaction: { to: TOKEN, data: approveData() } });
  const cases = [
    value => { value.receipt.status = 0; },
    value => { value.receipt.transactionHash = WRONG_HASH; },
    value => { value.receipt.logs[0].blockHash = WRONG_HASH; },
    value => { value.receipt.logs[0].removed = true; },
    value => { value.after.blockHash = WRONG_HASH; },
    value => { value.before.blockNumber = '100'; }
  ];
  for (const mutate of cases) {
    const changed = structuredClone(input); mutate(changed);
    assert.throws(() => verifyApprovePostcheck(changed, input.expected));
  }
  assert.throws(() => verifyApprovePostcheck({ ...input, receipt: { ...input.receipt, logs: [] } }, input.expected), { code: 'EVENT_COUNT' });
});

test('trusted expectation is separate and calldata cannot disagree with approval, grant or execute semantics', () => {
  const approval = approveInput(), approvalTrust = structuredClone(approval.expected);
  const forgedExpectation = structuredClone(approval);
  forgedExpectation.expected.semantics.token = RECIPIENT;
  assert.throws(() => verifyApprovePostcheck(forgedExpectation, approvalTrust), { code: 'TRUSTED_EXPECTATION_MISMATCH' });

  const approvalCalldata = structuredClone(approval);
  approvalCalldata.expected.transaction.data = '0x095ea7b3' + wordAddress(RECIPIENT) + wordUint(10000);
  approvalCalldata.transaction.data = approvalCalldata.expected.transaction.data;
  assert.throws(() => verifyApprovePostcheck(approvalCalldata, approvalCalldata.expected), { code: 'SEMANTIC_CALLDATA_MISMATCH' });

  const grant = grantInput();
  const changedGrant = structuredClone(grant);
  changedGrant.expected.transaction.data = changedGrant.expected.transaction.data.slice(0, 10 + 5 * 64) +
    wordAddress(RECIPIENT) + changedGrant.expected.transaction.data.slice(10 + 6 * 64);
  changedGrant.transaction.data = changedGrant.expected.transaction.data;
  assert.throws(() => verifyGrantPostcheck(changedGrant, changedGrant.expected), { code: 'SEMANTIC_CALLDATA_MISMATCH' });

  const execution = executeInput();
  const wrongMandate = structuredClone(execution);
  wrongMandate.before.state.mandate.asset = RECIPIENT;
  wrongMandate.after.state.mandate.asset = RECIPIENT;
  assert.throws(() => verifyExecutePostcheck(wrongMandate, execution.expected), { code: 'MANDATE_SEMANTICS_MISMATCH' });
  const wrongInnerRecipient = structuredClone(execution);
  wrongInnerRecipient.expected.transaction.data = executeData().replace(wordAddress(RECIPIENT), wordAddress(PROVIDER));
  wrongInnerRecipient.transaction.data = wrongInnerRecipient.expected.transaction.data;
  assert.throws(() => verifyExecutePostcheck(wrongInnerRecipient, wrongInnerRecipient.expected), { code: 'SEMANTIC_CALLDATA_MISMATCH' });
});
