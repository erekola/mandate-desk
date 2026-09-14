import test from 'node:test';
import assert from 'node:assert/strict';
import {
  KNOWN_AGENT,
  KNOWN_PRINCIPAL,
  TRANSFER_FROM_ACTION,
  TRANSFER_FROM_SELECTOR,
  createTransferFromIntent,
  sha256Canonical
} from '../src/brickken-intent.mjs';
import {
  PROVISIONED_EXECUTOR,
  buildOfflineActionSetupCall,
  buildOfflineExecutionCall
} from '../src/brickken-executor.mjs';
import {
  RAMS_REGISTRY,
  buildDirectMandatePlan,
  buildDirectRevokePlan
} from '../src/brickken-mandate.mjs';
import {
  DIRECT_LIFECYCLE_DEADLINE,
  EMPTY_METADATA,
  EMPTY_SIGNATURE,
  buildOfflineDirectGrantCall,
  buildOfflineDirectRevokeCall
} from '../src/brickken-lifecycle.mjs';
import {
  SANDBOX_IDENTITY_REF,
  buildExpectedExecutionPreparation,
  validateExecutePrepareResponse
} from '../src/brickken-prepare.mjs';
import {
  APPROVE_SELECTOR,
  UNSIGNED_ENVELOPE_ACTIONS,
  buildApproveEnvelope,
  buildExecuteEnvelope,
  buildGrantEnvelope,
  buildRevokeEnvelope,
  buildSetActionEnvelope,
  decodeApproveExecutor,
  encodeApproveExecutor,
  validateUnsignedEnvelope
} from '../src/brickken-envelope.mjs';

const NOW = 1_800_000_000;
const TOKEN = '0x5555555555555555555555555555555555555555';
const RECIPIENT = '0x6666666666666666666666666666666666666666';
const PROVIDER = '0xa90d2503d5d9b80ecc27856ff76f892b8c02f278';

function fixture() {
  const executionCall = buildOfflineExecutionCall(createTransferFromIntent({
    chainId: '11155111', principal: KNOWN_PRINCIPAL, agent: KNOWN_AGENT,
    executor: PROVISIONED_EXECUTOR, token: TOKEN, recipient: RECIPIENT,
    action: { selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: true, amountIndex: 2 },
    maxTransactionValue: '100', maxCumulativeValue: '100', cumulativeUsed: '0', allowance: '100'
  }, { from: KNOWN_PRINCIPAL, to: RECIPIENT, amount: '100' }));
  const mandatePlan = buildDirectMandatePlan(
    executionCall, { validFrom: NOW, validUntil: NOW + 300 }, NOW
  );
  const revokePlan = buildDirectRevokePlan();
  const grantReference = {
    schemaVersion: 1, kind: 'rams-direct-grant-reference', mandatePlanHash: mandatePlan.planHash,
    executionCallHash: executionCall.callHash, registry: RAMS_REGISTRY,
    caller: KNOWN_PRINCIPAL, agent: KNOWN_AGENT, principal: KNOWN_PRINCIPAL,
    complianceProvider: PROVIDER, identityRef: SANDBOX_IDENTITY_REF, asset: TOKEN,
    maxTransactionValue: '100', maxCumulativeValue: '100', validFrom: NOW,
    validUntil: NOW + 300, metadata: EMPTY_METADATA, actions: [TRANSFER_FROM_ACTION],
    deadline: DIRECT_LIFECYCLE_DEADLINE, signature: EMPTY_SIGNATURE
  };
  const revokeReference = {
    schemaVersion: 1, kind: 'rams-direct-revoke-reference', revokePlanHash: revokePlan.planHash,
    mandatePlanHash: mandatePlan.planHash, registry: RAMS_REGISTRY,
    caller: KNOWN_PRINCIPAL, agent: KNOWN_AGENT, principal: KNOWN_PRINCIPAL,
    deadline: DIRECT_LIFECYCLE_DEADLINE, signature: EMPTY_SIGNATURE
  };
  const grantCall = buildOfflineDirectGrantCall(
    mandatePlan, executionCall, NOW, grantReference
  );
  const revokeCall = buildOfflineDirectRevokeCall(
    revokePlan, mandatePlan, executionCall, NOW, revokeReference
  );
  const binding = {
    nonce: '7', type: 2, gasLimit: '150000',
    maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000'
  };
  const guard = {
    identityRef: SANDBOX_IDENTITY_REF,
    provisioningEvidenceSha256: 'a'.repeat(64), observedAt: NOW, expiresAt: NOW + 300,
    approvalHash: 'b'.repeat(64), approvedAt: NOW, approvalExpiresAt: NOW + 300,
    maxGasLimit: '200000', maxPriorityFeePerGas: '1500000000',
    maxFeePerGas: '3000000000', maxTotalGasCost: '400000000000000'
  };
  const preparationExpectation = buildExpectedExecutionPreparation(
    executionCall, { nonce: binding.nonce, type: binding.type }, {
      identityRef: guard.identityRef,
      provisioningEvidenceSha256: guard.provisioningEvidenceSha256,
      observedAt: guard.observedAt,
      expiresAt: guard.expiresAt,
      maxGasLimit: guard.maxGasLimit,
      maxPriorityFeePerGas: guard.maxPriorityFeePerGas,
      maxFeePerGas: guard.maxFeePerGas,
      maxTotalGasCost: guard.maxTotalGasCost
    }
  );
  const preparation = validateExecutePrepareResponse(JSON.stringify({
    transactions: [{ ...preparationExpectation.expected.transaction,
      gasLimit: binding.gasLimit,
      maxPriorityFeePerGas: binding.maxPriorityFeePerGas,
      maxFeePerGas: binding.maxFeePerGas }],
    txId: 'batch-001'
  }), preparationExpectation, NOW + 1);
  return {
    executionCall, mandatePlan, revokePlan, grantReference, revokeReference,
    grantCall, revokeCall, binding, guard, preparationExpectation, preparation
  };
}

function envelopes() {
  const f = fixture();
  return {
    f,
    values: [
      buildSetActionEnvelope(buildOfflineActionSetupCall(), f.binding, f.guard, NOW + 1),
      buildApproveEnvelope(f.executionCall, '100', f.binding, f.guard, NOW + 1),
      buildGrantEnvelope({ grantCall: f.grantCall, mandatePlan: f.mandatePlan,
        executionCall: f.executionCall, reference: f.grantReference }, f.binding, f.guard, NOW + 1),
      buildExecuteEnvelope({ preparation: f.preparation,
        preparationExpectation: f.preparationExpectation,
        trustedPreparationHash: f.preparation.preparationHash }, f.binding, f.guard, NOW + 1),
      buildRevokeEnvelope({ revokeCall: f.revokeCall, revokePlan: f.revokePlan,
        mandatePlan: f.mandatePlan, executionCall: f.executionCall,
        reference: f.revokeReference }, f.binding, f.guard, NOW + 1)
    ]
  };
}

test('all five builders emit exact complete type-2 unsigned envelopes with false signing claims', () => {
  const { values } = envelopes();
  assert.deepEqual(values.map(value => value.action), UNSIGNED_ENVELOPE_ACTIONS);
  for (const value of values) {
    assert.deepEqual(Object.keys(value.transaction), [
      'chainId', 'from', 'to', 'value', 'data', 'nonce', 'gasLimit', 'type',
      'maxPriorityFeePerGas', 'maxFeePerGas'
    ]);
    assert.equal(value.transaction.chainId, '11155111');
    assert.equal(value.transaction.type, 2);
    assert.equal(value.transaction.value, '0');
    assert.equal(value.scope.completeTransaction, true);
    assert.equal(value.scope.calldataSemanticsValidated, true);
    assert.equal(value.scope.evidenceAndApprovalWindowValid, true);
    assert.equal(value.scope.evidenceAuthenticityVerified, false);
    assert.equal(value.scope.approvalAuthenticityVerified, false);
    assert.equal(value.scope.trustedExpectationRequired, true);
    for (const key of ['provisioningReady', 'signingReady', 'chainWriteAuthorized']) {
      assert.equal(value.scope[key], false);
    }
    const result = validateUnsignedEnvelope(
      structuredClone(value), structuredClone(value), NOW + 1
    );
    assert.deepEqual(result.expectation, value);
    assert.deepEqual(result.transaction, value.transaction);
  }
  assert.equal(values.find(value => value.action === 'setAction').transaction.from, KNOWN_PRINCIPAL);
  assert.equal(values.find(value => value.action === 'approve').transaction.from, KNOWN_PRINCIPAL);
  assert.equal(values.find(value => value.action === 'grant').transaction.to, RAMS_REGISTRY);
  assert.equal(values.find(value => value.action === 'revoke').transaction.to, RAMS_REGISTRY);
  assert.equal(values.find(value => value.action === 'execute').transaction.from, KNOWN_AGENT);
  assert.equal(values.find(value => value.action === 'execute').transaction.to, PROVISIONED_EXECUTOR);
});

test('ERC-20 approval is exact, finite and bound to the policy allowance and executor', () => {
  const { f } = envelopes();
  const data = encodeApproveExecutor('100');
  assert.equal(APPROVE_SELECTOR, '0x095ea7b3');
  assert.equal((data.length - 2) / 2, 68);
  assert.deepEqual(decodeApproveExecutor(data, '100'), {
    spender: PROVISIONED_EXECUTOR, amount: '100'
  });
  const approved = buildApproveEnvelope(f.executionCall, '100', f.binding, f.guard, NOW + 1);
  assert.equal(approved.transaction.to, TOKEN);
  assert.equal(approved.transaction.data, data);
  for (const amount of ['0', '99', ((1n << 256n) - 1n).toString()]) {
    assert.throws(() => buildApproveEnvelope(
      f.executionCall, amount, f.binding, f.guard, NOW + 1
    ));
  }
  for (const bad of [data.slice(0, -2), data + '00', '0xdeadbeef' + data.slice(10),
    data.slice(0, 10) + '01' + data.slice(12), data.slice(0, -64) + '0'.repeat(63) + '1']) {
    assert.throws(() => decodeApproveExecutor(bad, '100'));
  }
});

test('trusted expectation rejects every transaction, source, guard, scope and hash mutation', () => {
  const { values } = envelopes();
  const transactionChanges = {
    chainId: '1', from: KNOWN_AGENT, to: RECIPIENT, value: '1', data: '0x12345678',
    nonce: '8', gasLimit: '140000', type: 0,
    maxPriorityFeePerGas: '900000000', maxFeePerGas: '1900000000'
  };
  for (const original of values) {
    for (const [field, changedValue] of Object.entries(transactionChanges)) {
      const changed = structuredClone(original);
      changed.transaction[field] = changedValue === original.transaction[field]
        ? (field === 'from' ? KNOWN_PRINCIPAL : KNOWN_AGENT)
        : changedValue;
      const { envelopeHash: ignored, ...payload } = changed;
      changed.envelopeHash = sha256Canonical(payload);
      assert.throws(() => validateUnsignedEnvelope(changed, original, NOW + 1));
    }
    for (const mutate of [
      value => { value.schemaVersion = 2; },
      value => { value.kind = 'other'; },
      value => { value.action = value.action === 'approve' ? 'grant' : 'approve'; },
      value => { value.sourceHash = 'c'.repeat(64); },
      value => { value.guard.approvalHash = 'c'.repeat(64); },
      value => { value.guard.maxTotalGasCost = '399999999999999'; },
      value => { value.scope.signingReady = true; },
      value => { value.extra = true; }
    ]) {
      const changed = structuredClone(original);
      mutate(changed);
      const { envelopeHash: ignored, ...payload } = changed;
      changed.envelopeHash = sha256Canonical(payload);
      assert.throws(() => validateUnsignedEnvelope(changed, original, NOW + 1));
    }
  }
});

test('evidence, owner approval and all four resource ceilings fail closed', () => {
  const f = fixture();
  for (const now of [NOW - 1, NOW + 300, 0, NaN, Infinity]) {
    assert.throws(() => buildSetActionEnvelope(
      buildOfflineActionSetupCall(), f.binding, f.guard, now
    ));
  }
  for (const change of [
    { expiresAt: NOW + 301 },
    { approvedAt: NOW - 1 },
    { approvalExpiresAt: NOW + 301 },
    { approvalHash: 'bad' },
    { provisioningEvidenceSha256: 'bad' },
    { identityRef: '0x' + '11'.repeat(32) },
    { maxGasLimit: '149999' },
    { maxPriorityFeePerGas: '999999999' },
    { maxFeePerGas: '1999999999' },
    { maxTotalGasCost: '299999999999999' },
    { maxGasLimit: '0' }
  ]) {
    assert.throws(() => buildSetActionEnvelope(
      buildOfflineActionSetupCall(), f.binding, { ...f.guard, ...change }, NOW + 1
    ));
  }
});

test('execute binds the N2 preparation, prepared nonce/fees and identical guard context', () => {
  const f = fixture();
  for (const change of [
    { nonce: '8' }, { type: 0 }, { gasLimit: '149999' },
    { maxPriorityFeePerGas: '999999999' }, { maxFeePerGas: '1999999999' }
  ]) {
    assert.throws(() => buildExecuteEnvelope(
      { preparation: f.preparation, preparationExpectation: f.preparationExpectation,
        trustedPreparationHash: f.preparation.preparationHash },
      { ...f.binding, ...change }, f.guard, NOW + 1
    ));
  }
  assert.throws(() => buildExecuteEnvelope(
    { preparation: f.preparation, preparationExpectation: f.preparationExpectation },
    f.binding, f.guard, NOW + 1
  ), { code: 'STRUCTURE' });
  const changedPreparation = structuredClone(f.preparation);
  changedPreparation.transaction.gasLimit = '140000';
  const { preparationHash: ignored, ...payload } = changedPreparation;
  changedPreparation.preparationHash = sha256Canonical(payload);
  assert.throws(() => buildExecuteEnvelope(
    { preparation: changedPreparation, preparationExpectation: f.preparationExpectation,
      trustedPreparationHash: f.preparation.preparationHash },
    { ...f.binding, gasLimit: '140000' }, f.guard, NOW + 1
  ));
  assert.throws(() => buildExecuteEnvelope(
    { preparation: f.preparation, preparationExpectation: f.preparationExpectation,
      trustedPreparationHash: f.preparation.preparationHash },
    f.binding, { ...f.guard, provisioningEvidenceSha256: 'c'.repeat(64) }, NOW + 1
  ), { code: 'PREPARATION_GUARD' });
});
