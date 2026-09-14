import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import {
  KNOWN_AGENT, KNOWN_PRINCIPAL, TRANSFER_FROM_ACTION, TRANSFER_FROM_SELECTOR,
  createTransferFromIntent, sha256Canonical
} from '../src/brickken-intent.mjs';
import { buildOfflineExecutionCall, PROVISIONED_EXECUTOR } from '../src/brickken-executor.mjs';
import { buildDirectMandatePlan, buildDirectRevokePlan, RAMS_REGISTRY } from '../src/brickken-mandate.mjs';
import {
  DIRECT_LIFECYCLE_DEADLINE, EMPTY_METADATA, EMPTY_SIGNATURE,
  GRANT_MANDATE_SELECTOR, REVOKE_MANDATE_SELECTOR,
  buildOfflineDirectGrantCall, buildOfflineDirectRevokeCall,
  decodeDirectGrantMandateCalldata, decodeDirectRevokeMandateCalldata,
  encodeDirectGrantMandateCalldata, encodeDirectRevokeMandateCalldata,
  validateOfflineDirectGrantCall, validateOfflineDirectRevokeCall
} from '../src/brickken-lifecycle.mjs';

const require = createRequire(import.meta.url);
const ethers = require('../vendor/ethers-6.17.0/ethers.umd.min.cjs');
const NOW = 1_800_000_000;
const TOKEN = '0x5555555555555555555555555555555555555555';
const RECIPIENT = '0x6666666666666666666666666666666666666666';
const IDENTITY = '0x6cc959e8598e56ce16688ac27025da562401e5a85fd3814d27ed69800f1f7633';
const PROVIDER = '0xa90d2503d5d9b80ecc27856ff76f892b8c02f278';
const lifecycleAbi = [
  'function grantMandate((address agent,uint48 validFrom,uint48 validUntil,address principal,address complianceProvider,bytes32 identityRef,address asset,uint256 maxTransactionValue,uint256 maxCumulativeValue,bytes32 metadata,bytes32[] actions,uint256 deadline) p,bytes signature)',
  'function revokeMandate(address agent,address principal,uint256 deadline,bytes signature)'
];
const iface = new ethers.Interface(lifecycleAbi);

function executionCall() {
  return buildOfflineExecutionCall(createTransferFromIntent({
    chainId: '11155111', principal: KNOWN_PRINCIPAL, agent: KNOWN_AGENT,
    executor: PROVISIONED_EXECUTOR, token: TOKEN, recipient: RECIPIENT,
    action: { selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: true, amountIndex: 2 },
    maxTransactionValue: '100', maxCumulativeValue: '200', cumulativeUsed: '0', allowance: '100'
  }, { from: KNOWN_PRINCIPAL, to: RECIPIENT, amount: '80' }));
}
function setup() {
  const call = executionCall();
  const mandate = buildDirectMandatePlan(call, { validFrom: NOW, validUntil: NOW + 3600 }, NOW);
  const revoke = buildDirectRevokePlan();
  const body = mandate.request.body;
  const grantReference = {
    schemaVersion: 1, kind: 'rams-direct-grant-reference', mandatePlanHash: mandate.planHash,
    executionCallHash: call.callHash, registry: RAMS_REGISTRY, caller: KNOWN_PRINCIPAL,
    agent: KNOWN_AGENT, principal: KNOWN_PRINCIPAL, complianceProvider: PROVIDER,
    identityRef: body.identityRef, asset: TOKEN, maxTransactionValue: '100',
    maxCumulativeValue: '200', validFrom: NOW, validUntil: NOW + 3600,
    metadata: EMPTY_METADATA, actions: [TRANSFER_FROM_ACTION],
    deadline: DIRECT_LIFECYCLE_DEADLINE, signature: EMPTY_SIGNATURE
  };
  const revokeReference = {
    schemaVersion: 1, kind: 'rams-direct-revoke-reference', revokePlanHash: revoke.planHash,
    mandatePlanHash: mandate.planHash, registry: RAMS_REGISTRY, caller: KNOWN_PRINCIPAL,
    agent: KNOWN_AGENT, principal: KNOWN_PRINCIPAL,
    deadline: DIRECT_LIFECYCLE_DEADLINE, signature: EMPTY_SIGNATURE
  };
  return { call, mandate, revoke, grantReference, revokeReference };
}
function replaceWord(data, index, value) {
  const start = 10 + index * 64;
  return data.slice(0, start) + BigInt(value).toString(16).padStart(64, '0') + data.slice(start + 64);
}

test('direct grant matches the exact verified public ABI and converts bytes4 API action to bytes32', () => {
  const s = setup();
  const data = encodeDirectGrantMandateCalldata(s.mandate, s.call, NOW, s.grantReference);
  const p = [KNOWN_AGENT, NOW, NOW + 3600, KNOWN_PRINCIPAL, PROVIDER, IDENTITY,
    TOKEN, 100n, 200n, EMPTY_METADATA, [TRANSFER_FROM_ACTION], 0n];
  const independent = iface.encodeFunctionData('grantMandate', [p, '0x']).toLowerCase();
  assert.equal(GRANT_MANDATE_SELECTOR, '0xc6a4ad00');
  assert.equal(data, independent);
  assert.equal((data.length - 2) / 2, 548);
  assert.deepEqual(decodeDirectGrantMandateCalldata(data, s.mandate, s.call, NOW, s.grantReference), {
    agent: KNOWN_AGENT, validFrom: String(NOW), validUntil: String(NOW + 3600),
    principal: KNOWN_PRINCIPAL, complianceProvider: PROVIDER, identityRef: IDENTITY,
    asset: TOKEN, maxTransactionValue: '100', maxCumulativeValue: '200',
    metadata: EMPTY_METADATA, actions: [TRANSFER_FROM_ACTION], deadline: '0', signature: '0x'
  });
});

test('direct revoke matches the exact verified public ABI with principal caller and empty signature', () => {
  const s = setup();
  const data = encodeDirectRevokeMandateCalldata(s.revoke, s.mandate, s.call, NOW, s.revokeReference);
  const independent = iface.encodeFunctionData('revokeMandate', [KNOWN_AGENT, KNOWN_PRINCIPAL, 0n, '0x']).toLowerCase();
  assert.equal(REVOKE_MANDATE_SELECTOR, '0x5e20639e');
  assert.equal(data, independent);
  assert.equal((data.length - 2) / 2, 164);
  assert.deepEqual(decodeDirectRevokeMandateCalldata(data, s.revoke, s.mandate, s.call, NOW, s.revokeReference), {
    agent: KNOWN_AGENT, principal: KNOWN_PRINCIPAL, deadline: '0', signature: '0x'
  });
});

test('grant artifact binds independent plan, execution call, reference, registry and false readiness flags', () => {
  const s = setup();
  const artifact = buildOfflineDirectGrantCall(s.mandate, s.call, NOW, s.grantReference);
  assert.equal(artifact.call.from, KNOWN_PRINCIPAL);
  assert.equal(artifact.call.to, RAMS_REGISTRY);
  assert.equal(artifact.call.value, '0');
  assert.equal(artifact.mandatePlanHash, s.mandate.planHash);
  assert.equal(artifact.referenceHash, sha256Canonical(s.grantReference));
  for (const key of ['provisioningReady', 'signingReady', 'chainWriteAuthorized']) assert.equal(artifact.scope[key], false);
  assert.deepEqual(validateOfflineDirectGrantCall(artifact, s.mandate, s.call, NOW, s.grantReference), artifact);
});

test('grant preparation permits future validFrom but remains bounded by creation and expiry', () => {
  const s = setup();
  const mandate = buildDirectMandatePlan(
    s.call,
    { validFrom: NOW + 300, validUntil: NOW + 1800 },
    NOW
  );
  const reference = {
    ...s.grantReference,
    mandatePlanHash: mandate.planHash,
    validFrom: NOW + 300,
    validUntil: NOW + 1800
  };
  const artifact = buildOfflineDirectGrantCall(mandate, s.call, NOW, reference);
  assert.deepEqual(validateOfflineDirectGrantCall(artifact, mandate, s.call, NOW, reference), artifact);
  for (const observedAt of [NOW - 1, NOW + 1800]) {
    assert.throws(
      () => buildOfflineDirectGrantCall(mandate, s.call, observedAt, reference),
      { code: 'MANDATE_WINDOW' }
    );
  }
  for (const invalid of [0, NaN, Infinity, NOW + 0.5, String(NOW)]) {
    assert.throws(
      () => buildOfflineDirectGrantCall(mandate, s.call, invalid, reference),
      { code: 'TIME' }
    );
  }
});

test('revoke artifact binds the exact revoke and mandate plans independently', () => {
  const s = setup();
  const artifact = buildOfflineDirectRevokeCall(s.revoke, s.mandate, s.call, NOW, s.revokeReference);
  assert.equal(artifact.call.from, KNOWN_PRINCIPAL);
  assert.equal(artifact.call.to, RAMS_REGISTRY);
  assert.equal(artifact.revokePlanHash, s.revoke.planHash);
  assert.equal(artifact.mandatePlanHash, s.mandate.planHash);
  assert.equal(artifact.referenceHash, sha256Canonical(s.revokeReference));
  for (const key of ['provisioningReady', 'signingReady', 'chainWriteAuthorized']) assert.equal(artifact.scope[key], false);
  assert.deepEqual(validateOfflineDirectRevokeCall(artifact, s.revoke, s.mandate, s.call, NOW, s.revokeReference), artifact);
});

test('revoke plan integrity is independent of the mandate activity window but now input remains exact', () => {
  const s = setup();
  for (const observedAt of [NOW - 600, NOW + 7200]) {
    const artifact = buildOfflineDirectRevokeCall(s.revoke, s.mandate, s.call, observedAt, s.revokeReference);
    assert.equal(artifact.call.data, encodeDirectRevokeMandateCalldata(
      s.revoke, s.mandate, s.call, observedAt, s.revokeReference
    ));
    assert.deepEqual(validateOfflineDirectRevokeCall(
      artifact, s.revoke, s.mandate, s.call, observedAt, s.revokeReference
    ), artifact);
  }
  for (const invalid of [0, -1, NaN, Infinity, NOW + 0.5, String(NOW)]) {
    assert.throws(() => buildOfflineDirectRevokeCall(
      s.revoke, s.mandate, s.call, invalid, s.revokeReference
    ), { code: 'TIME' });
  }
});

test('grant decoder rejects selector, exact length, offsets, uint48 overflow, action and empty-signature changes', () => {
  const s = setup();
  const data = encodeDirectGrantMandateCalldata(s.mandate, s.call, NOW, s.grantReference);
  const bad = [
    '0xdeadbeef' + data.slice(10), data.slice(0, -2), data + '00',
    replaceWord(data, 0, 32), replaceWord(data, 1, 480), replaceWord(data, 12, 352),
    replaceWord(data, 3, 1n << 48n), replaceWord(data, 14, 2),
    data.slice(0, 10 + 15 * 64) + 'ff'.repeat(32) + data.slice(10 + 16 * 64),
    replaceWord(data, 16, 1)
  ];
  for (const value of bad) assert.throws(() => decodeDirectGrantMandateCalldata(value, s.mandate, s.call, NOW, s.grantReference));
});

test('revoke decoder rejects operator/signature mode, selector, offsets, padding and trailing data', () => {
  const s = setup();
  const data = encodeDirectRevokeMandateCalldata(s.revoke, s.mandate, s.call, NOW, s.revokeReference);
  const signed = iface.encodeFunctionData('revokeMandate', [KNOWN_AGENT, KNOWN_PRINCIPAL, NOW + 60, '0x12']);
  for (const value of [
    '0xdeadbeef' + data.slice(10), data.slice(0, -2), data + '00',
    replaceWord(data, 3, 96), replaceWord(data, 4, 1), signed
  ]) assert.throws(() => decodeDirectRevokeMandateCalldata(value, s.revoke, s.mandate, s.call, NOW, s.revokeReference));
});

test('independent references reject changed caller, identities, registry, parameters and signatures', () => {
  const s = setup();
  for (const [key, value] of Object.entries({ caller: KNOWN_AGENT, principal: KNOWN_AGENT,
    registry: PROVISIONED_EXECUTOR, identityRef: '0x' + '11'.repeat(32), asset: RECIPIENT,
    maxTransactionValue: '101', deadline: '1', signature: '0x12' })) {
    const reference = structuredClone(s.grantReference); reference[key] = value;
    assert.throws(() => buildOfflineDirectGrantCall(s.mandate, s.call, NOW, reference), { code: 'REFERENCE_MISMATCH' });
  }
  for (const [key, value] of Object.entries({ caller: KNOWN_AGENT, registry: PROVISIONED_EXECUTOR,
    deadline: '1', signature: '0x12' })) {
    const reference = structuredClone(s.revokeReference); reference[key] = value;
    assert.throws(() => buildOfflineDirectRevokeCall(s.revoke, s.mandate, s.call, NOW, reference), { code: 'REFERENCE_MISMATCH' });
  }
});

test('artifact validation rejects calldata, hashes, scope, plan and unknown-field mutations', () => {
  const s = setup();
  const grant = buildOfflineDirectGrantCall(s.mandate, s.call, NOW, s.grantReference);
  for (const mutate of [
    value => { value.call.data += '00'; },
    value => { value.call.from = KNOWN_AGENT; },
    value => { value.call.to = PROVISIONED_EXECUTOR; },
    value => { value.referenceHash = '0'.repeat(64); },
    value => { value.lifecycleCallHash = '0'.repeat(64); },
    value => { value.scope.signingReady = true; },
    value => { value.extra = true; }
  ]) {
    const changed = structuredClone(grant); mutate(changed);
    assert.throws(() => validateOfflineDirectGrantCall(changed, s.mandate, s.call, NOW, s.grantReference));
  }
  const changedPlan = structuredClone(s.mandate);
  changedPlan.request.body.asset = RECIPIENT;
  assert.throws(() => buildOfflineDirectGrantCall(changedPlan, s.call, NOW, s.grantReference));
  const changedRevoke = structuredClone(s.revoke);
  changedRevoke.request.body.signerAddress = KNOWN_AGENT;
  assert.throws(() => buildOfflineDirectRevokeCall(changedRevoke, s.mandate, s.call, NOW, s.revokeReference));
});
