import test from 'node:test';
import assert from 'node:assert/strict';
import { createTransferFromIntent, KNOWN_PRINCIPAL, KNOWN_AGENT, TRANSFER_FROM_SELECTOR, sha256Canonical } from '../src/brickken-intent.mjs';
import { buildOfflineExecutionCall, PROVISIONED_EXECUTOR } from '../src/brickken-executor.mjs';
import { buildDirectMandatePlan, validateDirectMandatePlan, buildDirectRevokePlan, buildExecutePrepareRequest, RAMS_REGISTRY } from '../src/brickken-mandate.mjs';
const NOW = 1800000000;
function call(overrides = {}) {
  return buildOfflineExecutionCall(createTransferFromIntent({ chainId: '11155111', principal: KNOWN_PRINCIPAL, agent: KNOWN_AGENT,
    executor: PROVISIONED_EXECUTOR, token: '0x5555555555555555555555555555555555555555', recipient: '0x6666666666666666666666666666666666666666',
    action: { selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: true, amountIndex: 2 },
    maxTransactionValue: '100', maxCumulativeValue: '200', cumulativeUsed: '0', allowance: '100', ...overrides
  }, { from: KNOWN_PRINCIPAL, to: '0x6666666666666666666666666666666666666666', amount: '80' }));
}
const validity = { validFrom: NOW, validUntil: NOW + 3600 };

test('direct lifecycle binds principal, registry, identity, finite raw caps, exact asset/action and local recipient', () => {
  const c = call(), plan = buildDirectMandatePlan(c, validity, NOW), body = plan.request.body;
  assert.equal(body.signerAddress, KNOWN_PRINCIPAL);
  assert.equal(body.agent, KNOWN_AGENT);
  assert.equal(body.agentMandateAddress, RAMS_REGISTRY);
  assert.equal(body.asset, c.intent.policy.token);
  assert.equal(body.maxTransactionValue, '100');
  assert.deepEqual(body.actions, [TRANSFER_FROM_SELECTOR]);
  assert.equal(Object.hasOwn(body, 'signature'), false);
  assert.equal(Object.hasOwn(body, 'recipient'), false);
  assert.equal(plan.localRecipient, c.intent.policy.recipient);
  assert.equal(plan.scope.recipientEnforcedByLocalIntentOnly, true);
  assert.equal(plan.scope.lifecycleCalldataVerified, false);
  for (const key of ['provisioningReady', 'signingReady', 'chainWriteAuthorized']) assert.equal(plan.scope[key], false);
  assert.deepEqual(validateDirectMandatePlan(plan, c, NOW), plan);
  assert.equal(buildDirectRevokePlan().request.body.signerAddress, KNOWN_PRINCIPAL);
});

test('execute helper binds agent and dedicated executor without raw calldata override fields', () => {
  const c = call(), plan = buildDirectMandatePlan(c, validity, NOW);
  const result = buildExecutePrepareRequest(c, plan, NOW);
  assert.deepEqual(result.request.body, { chainId: '11155111', signerAddress: KNOWN_AGENT,
    executorAddress: PROVISIONED_EXECUTOR, asset: c.intent.policy.token, from: KNOWN_PRINCIPAL,
    to: c.intent.policy.recipient, amount: '80' });
  assert.equal(Object.hasOwn(result.request.body, 'data'), false);
});

test('local demo duration, start bounds, expiration and exact time input are enforced', () => {
  for (const invalid of [{ validFrom: NOW - 1, validUntil: NOW + 1 }, { validFrom: NOW + 301, validUntil: NOW + 600 },
    { validFrom: NOW, validUntil: NOW }, { validFrom: NOW, validUntil: NOW + 3601 },
    { validFrom: NOW + 0.5, validUntil: NOW + 60 }, { ...validity, extra: true }]) {
    assert.throws(() => buildDirectMandatePlan(call(), invalid, NOW));
  }
  const c = call(), plan = buildDirectMandatePlan(c, validity, NOW);
  for (const now of [NOW - 1, NOW + 3600, NaN]) assert.throws(() => buildExecutePrepareRequest(c, plan, now));
  const moved = structuredClone(plan);
  moved.request.body.validFrom += 3600; moved.request.body.validUntil += 3600;
  const { planHash: _hash, ...payload } = moved;
  moved.planHash = sha256Canonical(payload);
  assert.throws(() => validateDirectMandatePlan(moved, c, NOW + 3600));
});

test('tampering with request identities, actions, caps or plan scope is rejected', () => {
  const c = call(), original = buildDirectMandatePlan(c, validity, NOW);
  for (const [key, value] of Object.entries({ principal: KNOWN_AGENT, agent: KNOWN_PRINCIPAL, signerAddress: KNOWN_AGENT,
    asset: KNOWN_AGENT, identityRef: '0x' + 'b'.repeat(64), maxTransactionValue: '101', actions: ['0xffffffff'], signature: '0x1234' })) {
    const plan = structuredClone(original); plan.request.body[key] = value;
    assert.throws(() => buildExecutePrepareRequest(c, plan, NOW));
  }
  const bad = structuredClone(original); bad.scope.signingReady = true;
  assert.throws(() => validateDirectMandatePlan(bad, c, NOW));
});

test('new mandate requires zero usage, bounded allowance and finite caps', () => {
  const max = ((1n << 256n) - 1n).toString();
  for (const change of [{ cumulativeUsed: '1' }, { allowance: '201' }, { maxCumulativeValue: max },
    { maxTransactionValue: max, maxCumulativeValue: max }, { allowance: max }]) {
    assert.throws(() => buildDirectMandatePlan(call(change), validity, NOW));
  }
});
